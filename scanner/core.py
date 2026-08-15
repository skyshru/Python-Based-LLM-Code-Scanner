"""LLM client orchestration, prompt construction and response validation."""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

from pydantic import ValidationError

from .file_handler import (
    CodeChunk,
    SourceFile,
    UnreadableFileError,
    chunk_file,
    discover_files,
    number_lines,
    read_source_file,
)
from .models import (
    DEFAULT_MODEL,
    FileScanResult,
    LLMResponse,
    ScanReport,
    Severity,
    Vulnerability,
)

SYSTEM_PROMPT = """\
You are a senior application security engineer performing static analysis (SAST) \
on source code. You identify real, exploitable security vulnerabilities and you \
do not invent findings.

Analyze the provided source file for security flaws in these categories:
- OWASP Top 10 (2021): injection, broken access control, cryptographic failures, \
insecure design, security misconfiguration, vulnerable components, \
identification/authentication failures, software and data integrity failures, \
logging and monitoring failures, SSRF.
- Hardcoded secrets, API keys, credentials and private keys.
- Unsafe deserialization, command execution, path traversal, SSTI, XXE.
- Cloud and IaC misconfigurations (public buckets, permissive security groups, \
wildcard IAM policies, disabled encryption/logging, privileged containers, \
missing resource limits).
- Insecure cryptography (weak hashes, ECB mode, static IVs, disabled TLS \
verification).

Rules you MUST follow:
1. Report ONLY vulnerabilities you can point to in the supplied code. Never \
speculate about code, configuration files, or environment values you cannot see. \
Code that reads a secret from a config object, environment variable, or external \
file (e.g. `config['apiKey']`, `os.environ['TOKEN']`) is the CORRECT pattern, \
not a hardcoded-credential finding. Only report CWE-798 when the literal secret \
value itself appears in the code you were given (e.g. `api_key = "sk_live_..."`). \
Do not assume an external file you have not seen contains a real secret.
2. Do not report style issues, performance problems, or generic best practices \
that carry no security impact.
3. The `cwe_id` and `owasp_category` must accurately describe the actual flaw. \
Do not attach a security-sounding CWE to a reliability, compatibility, or \
code-quality issue that has no exploit path.
4. `line_number_range` must reference the absolute line numbers shown in the \
left gutter of the code you were given.
5. `code_patch.vulnerable_code` must be copied verbatim from the input; \
`code_patch.fixed_code` must be a working secure replacement in the same \
language, and must never remove or weaken an existing security control (e.g. \
do not delete escaping, validation, or auth checks as part of a "fix").
6. Severity reflects real-world exploitability and impact:
   - CRITICAL: remote unauthenticated compromise, RCE, live leaked credentials.
   - HIGH: injection, authn/authz bypass, sensitive data exposure.
   - MEDIUM: exploitable only with preconditions, weak crypto, missing hardening.
   - LOW: defense-in-depth gaps, informational hygiene issues.
7. Assign each finding a sequential id: SEC-001, SEC-002, ...
8. If the file contains no security vulnerabilities, return an empty \
`vulnerabilities` array. An empty result is a correct and expected answer.

Respond with JSON only, matching the requested schema exactly. No prose, no \
markdown fences.
"""

RESPONSE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "vulnerability_id": {"type": "string"},
                    "title": {"type": "string"},
                    "cwe_id": {"type": "string"},
                    "owasp_category": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    },
                    "file_path": {"type": "string"},
                    "line_number_range": {"type": "string"},
                    "description": {"type": "string"},
                    "remediation": {"type": "string"},
                    "code_patch": {
                        "type": "object",
                        "properties": {
                            "vulnerable_code": {"type": "string"},
                            "fixed_code": {"type": "string"},
                            "explanation": {"type": "string"},
                        },
                        "required": ["vulnerable_code", "fixed_code"],
                    },
                },
                "required": [
                    "vulnerability_id",
                    "title",
                    "cwe_id",
                    "owasp_category",
                    "severity",
                    "line_number_range",
                    "description",
                    "remediation",
                    "code_patch",
                ],
            },
        }
    },
    "required": ["vulnerabilities"],
}


class ScannerError(Exception):
    """Fatal, user-facing scanner error."""


class MissingAPIKeyError(ScannerError):
    pass


class DailyQuotaExceededError(ScannerError):
    """Raised when the provider's daily request quota is exhausted.

    Unlike a transient rate limit, retrying will not help until the quota
    resets, so this is never retried and always aborts the whole scan
    rather than just the current chunk.
    """


class LLMClient(Protocol):
    """Minimal surface the scanner needs; lets tests inject a fake."""

    def generate(self, system_prompt: str, user_prompt: str) -> str: ...


@dataclass
class RateLimitConfig:
    """Client-side pacing and retry policy."""

    requests_per_minute: int = 15
    max_retries: int = 4
    base_backoff_seconds: float = 2.0
    max_backoff_seconds: float = 60.0


class RateLimiter:
    """Simple sleep-based pacer that keeps us under a per-minute quota."""

    def __init__(self, requests_per_minute: int, sleep: Callable[[float], None] = time.sleep):
        self._min_interval = 60.0 / requests_per_minute if requests_per_minute > 0 else 0.0
        self._sleep = sleep
        self._last_call: float | None = None

    def acquire(self) -> None:
        if self._min_interval <= 0:
            return
        now = time.monotonic()
        if self._last_call is not None:
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                self._sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()


class GeminiClient:
    """Thin wrapper over `google-genai` with retry and quota handling."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        rate_limit: RateLimitConfig | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise MissingAPIKeyError(
                "GEMINI_API_KEY is not set. Add it to your environment or a .env "
                "file (see .env.example). Get a key at https://aistudio.google.com/apikey"
            )
        self.model = model
        self.config = rate_limit or RateLimitConfig()
        self._sleep = sleep
        self._limiter = RateLimiter(self.config.requests_per_minute, sleep=sleep)
        self._client = self._build_client()

    def _build_client(self):
        try:
            from google import genai
        except ImportError as exc:  # pragma: no cover - import guard
            raise ScannerError(
                "google-genai is not installed. Run: pip install google-genai"
            ) from exc

        # The SDK warns on every generate_content call that automatic function
        # calling is better used via Chat. We never pass tools, so the advice
        # does not apply and the warning is pure noise in scan output.
        logging.getLogger("google_genai.models").setLevel(logging.ERROR)

        return genai.Client(api_key=self.api_key)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            response_mime_type="application/json",
            response_schema=RESPONSE_SCHEMA,
            temperature=0.1,
        )

        last_error: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            self._limiter.acquire()
            try:
                response = self._client.models.generate_content(
                    model=self.model,
                    contents=user_prompt,
                    config=config,
                )
                text = getattr(response, "text", None)
                if not text:
                    raise ScannerError("Model returned an empty response")
                return text
            except Exception as exc:  # noqa: BLE001 - SDK raises varied types
                if _is_daily_quota_exhausted(exc):
                    raise DailyQuotaExceededError(
                        f"Daily request quota exhausted for model '{self.model}': {exc}"
                    ) from exc
                last_error = exc
                if not _is_retryable(exc) or attempt == self.config.max_retries:
                    break
                self._sleep(self._backoff_for(attempt))

        raise ScannerError(f"LLM request failed: {last_error}") from last_error

    def _backoff_for(self, attempt: int) -> float:
        delay = min(
            self.config.base_backoff_seconds * (2**attempt),
            self.config.max_backoff_seconds,
        )
        return delay + random.uniform(0, delay * 0.25)


_RETRYABLE_MARKERS = (
    "429",
    "500",
    "502",
    "503",
    "504",
    "resource_exhausted",
    "rate limit",
    "quota",
    "deadline",
    "timeout",
    "unavailable",
    "connection",
)


def _is_retryable(exc: Exception) -> bool:
    message = f"{type(exc).__name__} {exc}".lower()
    return any(marker in message for marker in _RETRYABLE_MARKERS)


# Google's daily-quota error is still nominally a 429 with a short suggested
# retryDelay, which makes it look retryable — but the quotaId names a PerDay
# metric, and no amount of short-delay retrying clears a daily cap. Detect it
# specifically so we fail the whole scan once instead of retrying (and then
# failing) on every remaining file.
_DAILY_QUOTA_MARKERS = ("perday",)


def _is_daily_quota_exhausted(exc: Exception) -> bool:
    message = f"{type(exc).__name__} {exc}".lower()
    return any(marker in message for marker in _DAILY_QUOTA_MARKERS)


def build_user_prompt(chunk: CodeChunk) -> str:
    """Render the per-chunk analysis request."""
    header = [
        f"File path: {chunk.file.relative_path}",
        f"Language: {chunk.file.language}",
    ]
    if not chunk.is_whole_file:
        header.append(
            f"Segment {chunk.index + 1} of {chunk.total} "
            f"(lines {chunk.start_line}-{chunk.end_line} of the full file). "
            "Analyze only what is shown; ignore references defined elsewhere."
        )
    body = number_lines(chunk.content, start_line=chunk.start_line)
    return (
        "\n".join(header)
        + "\n\nSource code (line numbers in the left gutter are authoritative):\n"
        + "```\n"
        + body
        + "\n```\n\nReturn the JSON object of findings."
    )


def parse_llm_response(raw: str) -> LLMResponse:
    """Validate the model output, tolerating fenced or prose-wrapped JSON."""
    payload = _extract_json(raw)
    try:
        return LLMResponse.model_validate(payload)
    except ValidationError as exc:
        raise ScannerError(f"Model returned a response that failed validation: {exc}") from exc


def _extract_json(raw: str) -> dict:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise ScannerError("Model response did not contain JSON") from None
        try:
            payload = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ScannerError(f"Model response was not valid JSON: {exc}") from exc

    if isinstance(payload, list):
        payload = {"vulnerabilities": payload}
    if not isinstance(payload, dict):
        raise ScannerError("Model response JSON was not an object")
    return payload


def _dedupe(findings: Sequence[Vulnerability]) -> list[Vulnerability]:
    """Drop duplicates produced by overlapping chunk windows."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Vulnerability] = []
    for finding in findings:
        key = (finding.cwe_id, finding.line_number_range, finding.title.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _renumber(findings: list[Vulnerability]) -> list[Vulnerability]:
    for i, finding in enumerate(findings, start=1):
        finding.vulnerability_id = f"SEC-{i:03d}"
    return findings


class Scanner:
    """Orchestrates discovery, chunking, LLM calls and result assembly."""

    def __init__(
        self,
        client: LLMClient,
        model: str = DEFAULT_MODEL,
        severity_threshold: Severity = Severity.LOW,
        chunk_lines: int | None = None,
    ):
        self.client = client
        self.model = model
        self.severity_threshold = severity_threshold
        self.chunk_lines = chunk_lines

    def scan_file(self, source: SourceFile) -> FileScanResult:
        chunks = chunk_file(
            source,
            **({"chunk_lines": self.chunk_lines} if self.chunk_lines else {}),
        )
        findings: list[Vulnerability] = []
        errors: list[str] = []

        for chunk in chunks:
            try:
                raw = self.client.generate(SYSTEM_PROMPT, build_user_prompt(chunk))
                parsed = parse_llm_response(raw)
            except DailyQuotaExceededError:
                # Not file-level noise: propagate so scan() can stop the
                # whole run instead of limping through every remaining file.
                raise
            except ScannerError as exc:
                errors.append(str(exc))
                continue

            for finding in parsed.vulnerabilities:
                finding.file_path = source.relative_path
                findings.append(finding)

        findings = [f for f in findings if f.severity >= self.severity_threshold]
        findings.sort(key=lambda f: (-f.severity.rank, f.line_number_range))
        findings = _renumber(_dedupe(findings))

        return FileScanResult(
            file_path=source.relative_path,
            language=source.language,
            scanned=len(errors) < len(chunks) if chunks else False,
            error="; ".join(errors) if errors else None,
            vulnerabilities=findings,
        )

    def scan(
        self,
        target: str | Path,
        on_file_start: Callable[[str, int, int], None] | None = None,
        on_file_done: Callable[[FileScanResult], None] | None = None,
    ) -> ScanReport:
        target_path = Path(target)
        paths = discover_files(target_path)

        report = ScanReport(
            model=self.model,
            target=str(target_path),
            severity_threshold=self.severity_threshold,
        )

        for i, path in enumerate(paths, start=1):
            display = _display_path(path, target_path)
            if on_file_start:
                on_file_start(display, i, len(paths))

            try:
                source = read_source_file(path, base=target_path)
            except UnreadableFileError as exc:
                result = FileScanResult(
                    file_path=display,
                    scanned=False,
                    error=str(exc),
                )
            else:
                try:
                    result = self.scan_file(source)
                except DailyQuotaExceededError as exc:
                    # Every remaining file would fail identically, so mark
                    # them all at once instead of retrying-then-failing each
                    # one individually.
                    remaining = paths[i - 1 :]
                    report.truncated = True
                    report.truncation_reason = (
                        f"Stopped after {i - 1} of {len(paths)} files "
                        f"({len(remaining)} not attempted): {exc}"
                    )
                    for skipped_path in remaining:
                        skipped_result = FileScanResult(
                            file_path=_display_path(skipped_path, target_path),
                            scanned=False,
                            error="skipped: daily API quota exhausted; scan stopped early",
                        )
                        report.results.append(skipped_result)
                        if on_file_done:
                            on_file_done(skipped_result)
                    break

            report.results.append(result)
            if on_file_done:
                on_file_done(result)

        report.rebuild_summary(files_discovered=len(paths))
        return report


def _display_path(path: Path, target: Path) -> str:
    root = target.parent if target.is_file() else target
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
