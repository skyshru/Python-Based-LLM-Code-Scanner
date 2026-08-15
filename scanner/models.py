"""Pydantic schemas for vulnerabilities, scan results and reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Single source of truth for the default model id; `core` re-exports it so the
# dependency direction stays core -> models.
DEFAULT_MODEL = "gemini-3.7-flash"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class CodePatch(BaseModel):
    """Before/after snippet demonstrating the secure refactor."""

    model_config = ConfigDict(extra="ignore")

    vulnerable_code: str = Field(description="The insecure code as it appears today.")
    fixed_code: str = Field(description="The rewritten, secure version of the snippet.")
    explanation: str = Field(
        default="",
        description="Why the replacement removes the flaw.",
    )


class Vulnerability(BaseModel):
    """A single finding produced by the LLM for one file."""

    model_config = ConfigDict(extra="ignore")

    vulnerability_id: str = Field(description='Stable id such as "SEC-001".')
    title: str
    cwe_id: str = Field(description='CWE reference such as "CWE-89".')
    owasp_category: str = Field(description='OWASP category such as "A03:2021-Injection".')
    severity: Severity
    file_path: str = ""
    line_number_range: str = Field(
        default="unknown",
        description='Affected lines, e.g. "42" or "42-57".',
    )
    description: str
    remediation: str
    code_patch: CodePatch
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("line_number_range", mode="before")
    @classmethod
    def _normalize_line_range(cls, value: Any) -> str:
        """Accept ints, [start, end] lists and tuples as well as strings."""
        if value is None:
            return "unknown"
        if isinstance(value, (list, tuple)):
            parts = [str(p) for p in value if p is not None]
            if not parts:
                return "unknown"
            if len(parts) == 1:
                return parts[0]
            return f"{parts[0]}-{parts[-1]}"
        return str(value)

    @field_validator("cwe_id", mode="before")
    @classmethod
    def _normalize_cwe(cls, value: Any) -> str:
        if value is None:
            return "CWE-UNKNOWN"
        text = str(value).strip()
        if text.isdigit():
            return f"CWE-{text}"
        return text


class LLMResponse(BaseModel):
    """Exact shape requested from the model for a single file."""

    model_config = ConfigDict(extra="ignore")

    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class FileScanResult(BaseModel):
    """Outcome of scanning one file, including failures."""

    model_config = ConfigDict(extra="ignore")

    file_path: str
    language: str = "unknown"
    scanned: bool = True
    error: str | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class ScanSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    files_discovered: int = 0
    files_scanned: int = 0
    files_failed: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)


class ScanReport(BaseModel):
    """Top-level report serialized to JSON / Markdown / terminal."""

    model_config = ConfigDict(extra="ignore")

    tool: str = "llm-appsec-scanner"
    version: str = "0.1.0"
    model: str = DEFAULT_MODEL
    target: str = ""
    severity_threshold: Severity = Severity.LOW
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: ScanSummary = Field(default_factory=ScanSummary)
    results: list[FileScanResult] = Field(default_factory=list)

    @property
    def findings(self) -> list[Vulnerability]:
        return [v for r in self.results for v in r.vulnerabilities]

    @property
    def has_actionable_findings(self) -> bool:
        return self.summary.total_findings > 0

    def rebuild_summary(self, files_discovered: int | None = None) -> None:
        findings = self.findings
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in findings:
            by_severity[finding.severity.value] += 1
        self.summary = ScanSummary(
            files_discovered=(
                files_discovered
                if files_discovered is not None
                else len(self.results)
            ),
            files_scanned=sum(1 for r in self.results if r.scanned and not r.error),
            files_failed=sum(1 for r in self.results if r.error),
            total_findings=len(findings),
            findings_by_severity=by_severity,
        )
