"""Unit tests with mocked LLM responses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from scanner.core import (
    DailyQuotaExceededError,
    GeminiClient,
    MissingAPIKeyError,
    RateLimitConfig,
    Scanner,
    ScannerError,
    _is_daily_quota_exhausted,
    _is_retryable,
    build_user_prompt,
    parse_llm_response,
)
from scanner.file_handler import (
    UnreadableFileError,
    chunk_file,
    discover_files,
    is_supported_file,
    number_lines,
    read_source_file,
    SourceFile,
)
from scanner.baseline import (
    Baseline,
    BaselineEntry,
    apply_baseline,
    load_baseline,
    save_baseline,
)
from scanner.baseline import update_baseline as merge_baseline
from scanner.models import FileScanResult, ScanReport, Severity, Vulnerability
from scanner.reporter import (
    _parse_line_region,
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
    write_report,
)

SAMPLES = Path(__file__).parent / "vulnerable_samples"


def _finding(severity: str = "HIGH", vid: str = "SEC-001", line: str = "18-20") -> dict:
    return {
        "vulnerability_id": vid,
        "title": "SQL Injection via Direct Parameter Concatenation",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "severity": severity,
        "file_path": "sample_sqli.py",
        "line_number_range": line,
        "description": "User input is concatenated into a SQL statement.",
        "remediation": "Use parameterized queries.",
        "code_patch": {
            "vulnerable_code": 'query = "SELECT * FROM users WHERE u = \'" + username + "\'"',
            "fixed_code": 'cursor.execute("SELECT * FROM users WHERE u = ?", (username,))',
            "explanation": "Placeholders keep data out of the SQL grammar.",
        },
    }


class FakeClient:
    """Deterministic stand-in for GeminiClient."""

    def __init__(self, responses: list[str] | str):
        self._responses = [responses] if isinstance(responses, str) else list(responses)
        self.calls: list[tuple[str, str]] = []

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append((system_prompt, user_prompt))
        if len(self._responses) == 1:
            return self._responses[0]
        return self._responses[len(self.calls) - 1]


class QuotaExhaustedClient:
    """Returns `responses` for the first `fail_after` calls, then raises forever."""

    def __init__(self, responses: list[str], fail_after: int):
        self._responses = responses
        self._fail_after = fail_after
        self.calls = 0

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        if self.calls > self._fail_after:
            raise DailyQuotaExceededError(
                "Daily request quota exhausted for model 'x': 429 RESOURCE_EXHAUSTED "
                "quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier"
            )
        return self._responses[self.calls - 1]


# --------------------------------------------------------------------------
# file_handler
# --------------------------------------------------------------------------


def test_supported_extensions_and_lockfile_exclusion(tmp_path: Path):
    assert is_supported_file(tmp_path / "app.py")
    assert is_supported_file(tmp_path / "main.tf")
    assert is_supported_file(tmp_path / "deploy.yaml")
    assert not is_supported_file(tmp_path / "logo.png")
    assert not is_supported_file(tmp_path / "package-lock.json")
    assert not is_supported_file(tmp_path / "yarn.lock")


def test_discover_files_skips_ignored_directories(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("var a = 1;\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "app.py").write_text("cached\n")
    (tmp_path / "README.md").write_text("docs\n")

    found = {p.name for p in discover_files(tmp_path)}
    assert found == {"app.py"}


def test_discover_files_single_file(tmp_path: Path):
    target = tmp_path / "one.py"
    target.write_text("print(1)\n")
    assert discover_files(target) == [target]


def test_discover_files_missing_target(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        discover_files(tmp_path / "nope")


def test_read_source_file_rejects_binary(tmp_path: Path):
    blob = tmp_path / "payload.py"
    blob.write_bytes(b"\x89PNG\x00\x00binary")
    with pytest.raises(UnreadableFileError, match="binary"):
        read_source_file(blob)


def test_read_source_file_rejects_empty(tmp_path: Path):
    empty = tmp_path / "empty.py"
    empty.write_text("")
    with pytest.raises(UnreadableFileError, match="empty"):
        read_source_file(empty)


def test_read_source_file_relative_path(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    target = tmp_path / "pkg" / "mod.py"
    target.write_text("a = 1\n")
    source = read_source_file(target, base=tmp_path)
    assert source.relative_path == "pkg/mod.py"
    assert source.language == "python"


def test_chunk_file_single_window():
    source = SourceFile(Path("a.py"), "a.py", "python", "\n".join(f"line{i}" for i in range(50)))
    chunks = chunk_file(source)
    assert len(chunks) == 1
    assert chunks[0].is_whole_file
    assert chunks[0].start_line == 1


def test_chunk_file_overlapping_windows():
    source = SourceFile(Path("big.py"), "big.py", "python", "\n".join(f"l{i}" for i in range(1000)))
    chunks = chunk_file(source, chunk_lines=400, overlap=20)
    assert len(chunks) > 1
    assert chunks[0].start_line == 1
    assert chunks[-1].end_line == 1000
    # Consecutive windows must overlap so straddling flaws stay visible.
    assert chunks[1].start_line <= chunks[0].end_line


def test_number_lines_uses_absolute_offsets():
    numbered = number_lines("alpha\nbeta", start_line=41)
    assert "41 | alpha" in numbered
    assert "42 | beta" in numbered


# --------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert Severity.HIGH >= Severity.HIGH


def test_line_range_accepts_tuple_and_int():
    v = Vulnerability.model_validate({**_finding(), "line_number_range": (10, 14)})
    assert v.line_number_range == "10-14"

    v = Vulnerability.model_validate({**_finding(), "line_number_range": 7})
    assert v.line_number_range == "7"


def test_cwe_id_normalized_from_bare_number():
    v = Vulnerability.model_validate({**_finding(), "cwe_id": "89"})
    assert v.cwe_id == "CWE-89"


def test_rebuild_summary_counts_by_severity():
    report = ScanReport()
    report.results = [
        Scanner(FakeClient("{}")).scan_file(
            SourceFile(Path("x.py"), "x.py", "python", "a = 1\n")
        )
    ]
    report.rebuild_summary()
    assert report.summary.total_findings == 0
    assert report.summary.findings_by_severity["HIGH"] == 0


# --------------------------------------------------------------------------
# response parsing
# --------------------------------------------------------------------------


def test_parse_plain_json():
    raw = json.dumps({"vulnerabilities": [_finding()]})
    parsed = parse_llm_response(raw)
    assert len(parsed.vulnerabilities) == 1
    assert parsed.vulnerabilities[0].severity is Severity.HIGH


def test_parse_fenced_json():
    raw = "```json\n" + json.dumps({"vulnerabilities": []}) + "\n```"
    assert parse_llm_response(raw).vulnerabilities == []


def test_parse_json_with_surrounding_prose():
    raw = "Here is the result:\n" + json.dumps({"vulnerabilities": [_finding()]}) + "\nDone."
    assert len(parse_llm_response(raw).vulnerabilities) == 1


def test_parse_bare_array_is_wrapped():
    raw = json.dumps([_finding()])
    assert len(parse_llm_response(raw).vulnerabilities) == 1


def test_parse_rejects_non_json():
    with pytest.raises(ScannerError, match="did not contain JSON"):
        parse_llm_response("I could not analyze this file.")


def test_parse_rejects_invalid_severity():
    bad = {"vulnerabilities": [{**_finding(), "severity": "SPICY"}]}
    with pytest.raises(ScannerError, match="failed validation"):
        parse_llm_response(json.dumps(bad))


# --------------------------------------------------------------------------
# prompting
# --------------------------------------------------------------------------


def test_user_prompt_includes_path_language_and_numbered_code():
    source = SourceFile(Path("a.py"), "svc/a.py", "python", "import os\nos.system(x)\n")
    prompt = build_user_prompt(chunk_file(source)[0])
    assert "svc/a.py" in prompt
    assert "python" in prompt
    assert "1 | import os" in prompt
    assert "Segment" not in prompt


def test_user_prompt_marks_segments_for_chunked_files():
    source = SourceFile(Path("b.py"), "b.py", "python", "\n".join(f"l{i}" for i in range(900)))
    chunks = chunk_file(source, chunk_lines=400, overlap=20)
    prompt = build_user_prompt(chunks[1])
    assert "Segment 2 of" in prompt


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------


def test_scan_file_attaches_path_and_parses_findings():
    client = FakeClient(json.dumps({"vulnerabilities": [_finding()]}))
    source = read_source_file(SAMPLES / "sample_sqli.py", base=SAMPLES)
    result = Scanner(client).scan_file(source)

    assert result.error is None
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].file_path == "sample_sqli.py"
    assert result.language == "python"


def test_scan_file_filters_below_threshold():
    payload = {
        "vulnerabilities": [
            _finding(severity="LOW", vid="SEC-001"),
            _finding(severity="CRITICAL", vid="SEC-002", line="30"),
        ]
    }
    client = FakeClient(json.dumps(payload))
    source = SourceFile(Path("a.py"), "a.py", "python", "x = 1\n")

    result = Scanner(client, severity_threshold=Severity.HIGH).scan_file(source)
    assert [v.severity for v in result.vulnerabilities] == [Severity.CRITICAL]


def test_scan_file_records_error_on_bad_response():
    client = FakeClient("not json at all")
    source = SourceFile(Path("a.py"), "a.py", "python", "x = 1\n")
    result = Scanner(client).scan_file(source)

    assert result.error is not None
    assert result.vulnerabilities == []


def test_findings_are_sorted_and_renumbered():
    payload = {
        "vulnerabilities": [
            _finding(severity="LOW", vid="SEC-009", line="5"),
            _finding(severity="CRITICAL", vid="SEC-002", line="9"),
            _finding(severity="MEDIUM", vid="SEC-007", line="12"),
        ]
    }
    client = FakeClient(json.dumps(payload))
    result = Scanner(client).scan_file(SourceFile(Path("a.py"), "a.py", "python", "x = 1\n"))

    assert [v.severity for v in result.vulnerabilities] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    assert [v.vulnerability_id for v in result.vulnerabilities] == [
        "SEC-001",
        "SEC-002",
        "SEC-003",
    ]


def test_duplicate_findings_from_overlapping_chunks_are_deduped():
    duplicate = json.dumps({"vulnerabilities": [_finding(), _finding(vid="SEC-002")]})
    client = FakeClient(duplicate)
    result = Scanner(client).scan_file(SourceFile(Path("a.py"), "a.py", "python", "x = 1\n"))
    assert len(result.vulnerabilities) == 1


def test_scan_directory_builds_summary(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\nos.system(cmd)\n")
    (tmp_path / "b.py").write_text("x = 1\n")

    responses = [
        json.dumps({"vulnerabilities": [_finding(severity="CRITICAL")]}),
        json.dumps({"vulnerabilities": []}),
    ]
    report = Scanner(FakeClient(responses), model="gemini-3.7-flash").scan(tmp_path)

    assert report.summary.files_discovered == 2
    assert report.summary.files_scanned == 2
    assert report.summary.total_findings == 1
    assert report.summary.findings_by_severity["CRITICAL"] == 1
    assert report.has_actionable_findings


def test_scan_reports_clean_when_no_findings(tmp_path: Path):
    (tmp_path / "safe.py").write_text("def add(a, b):\n    return a + b\n")
    report = Scanner(FakeClient(json.dumps({"vulnerabilities": []}))).scan(tmp_path)

    assert report.summary.total_findings == 0
    assert not report.has_actionable_findings


def test_scan_continues_past_unreadable_file(tmp_path: Path):
    (tmp_path / "good.py").write_text("x = 1\n")
    (tmp_path / "bad.py").write_bytes(b"\x00\x01\x02binary")

    report = Scanner(FakeClient(json.dumps({"vulnerabilities": []}))).scan(tmp_path)
    assert report.summary.files_discovered == 2
    assert report.summary.files_failed == 1


def test_scan_progress_callbacks_fire(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    seen: list[str] = []

    Scanner(FakeClient(json.dumps({"vulnerabilities": []}))).scan(
        tmp_path,
        on_file_start=lambda p, i, t: seen.append(p),
    )
    assert seen == ["a.py"]


def test_scan_file_propagates_daily_quota_exceeded():
    class RaisingClient:
        def generate(self, system_prompt, user_prompt):
            raise DailyQuotaExceededError("quota gone")

    source = SourceFile(Path("a.py"), "a.py", "python", "x = 1\n")
    with pytest.raises(DailyQuotaExceededError):
        Scanner(RaisingClient()).scan_file(source)


def test_scan_stops_early_on_daily_quota_exhaustion(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    (tmp_path / "c.py").write_text("z = 3\n")

    client = QuotaExhaustedClient(
        responses=[json.dumps({"vulnerabilities": [_finding(severity="CRITICAL")]})],
        fail_after=1,
    )
    report = Scanner(client).scan(tmp_path)

    assert report.truncated is True
    assert "1 of 3" in report.truncation_reason
    assert "2 not attempted" in report.truncation_reason
    assert report.summary.files_discovered == 3

    scanned_with_findings = [r for r in report.results if r.vulnerabilities]
    assert len(scanned_with_findings) == 1

    skipped = [r for r in report.results if r.error and "quota exhausted" in r.error]
    assert len(skipped) == 2
    assert all(not r.scanned for r in skipped)


def test_scan_stop_early_still_fires_on_file_done_for_skipped_files(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")

    client = QuotaExhaustedClient(responses=[], fail_after=0)
    done: list[str] = []
    Scanner(client).scan(tmp_path, on_file_done=lambda r: done.append(r.file_path))

    assert done == ["a.py", "b.py"]


# --------------------------------------------------------------------------
# API key / retry handling
# --------------------------------------------------------------------------


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(MissingAPIKeyError, match="GEMINI_API_KEY"):
        GeminiClient()


@pytest.mark.parametrize(
    "message",
    [
        "429 RESOURCE_EXHAUSTED: quota exceeded",
        "503 Service Unavailable",
        "Connection reset by peer",
        "Deadline exceeded",
    ],
)
def test_retryable_errors_detected(message):
    assert _is_retryable(Exception(message))


@pytest.mark.parametrize("message", ["400 Invalid argument", "401 Unauthorized"])
def test_non_retryable_errors_detected(message):
    assert not _is_retryable(Exception(message))


def test_daily_quota_marker_detected():
    exc = RuntimeError(
        "429 RESOURCE_EXHAUSTED. quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier"
    )
    assert _is_daily_quota_exhausted(exc)


def test_daily_quota_marker_not_confused_with_per_minute_limit():
    exc = RuntimeError("429 RESOURCE_EXHAUSTED: rate limit exceeded, retry in 2s")
    assert not _is_daily_quota_exhausted(exc)


def test_client_fails_fast_on_daily_quota(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    class FakeModels:
        calls = 0

        def generate_content(self, model, contents, config):
            FakeModels.calls += 1
            raise RuntimeError(
                "429 RESOURCE_EXHAUSTED. quotaId: "
                "GenerateRequestsPerDayPerProjectPerModel-FreeTier"
            )

    client = GeminiClient.__new__(GeminiClient)
    client.api_key = "test-key"
    client.model = "gemini-3.7-flash"
    client.config = RateLimitConfig(requests_per_minute=0, max_retries=4, base_backoff_seconds=0)
    slept: list[float] = []
    client._sleep = slept.append
    from scanner.core import RateLimiter

    client._limiter = RateLimiter(0, sleep=lambda _s: None)
    client._client = type("C", (), {"models": FakeModels()})()

    with pytest.raises(DailyQuotaExceededError):
        client.generate("sys", "user")
    assert FakeModels.calls == 1, "must not retry a daily-quota error"
    assert slept == [], "must not sleep/backoff on a daily-quota error"


def test_client_retries_then_succeeds(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    payload = json.dumps({"vulnerabilities": []})
    attempts = {"n": 0}

    class FakeModels:
        def generate_content(self, model, contents, config):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise RuntimeError("429 RESOURCE_EXHAUSTED")
            return type("R", (), {"text": payload})()

    client = GeminiClient.__new__(GeminiClient)
    client.api_key = "test-key"
    client.model = "gemini-3.7-flash"
    client.config = RateLimitConfig(requests_per_minute=0, max_retries=4, base_backoff_seconds=0)
    client._sleep = lambda _s: None
    from scanner.core import RateLimiter

    client._limiter = RateLimiter(0, sleep=lambda _s: None)
    client._client = type("C", (), {"models": FakeModels()})()

    assert client.generate("sys", "user") == payload
    assert attempts["n"] == 3


def test_client_gives_up_on_non_retryable(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    class FakeModels:
        calls = 0

        def generate_content(self, model, contents, config):
            FakeModels.calls += 1
            raise RuntimeError("400 INVALID_ARGUMENT")

    client = GeminiClient.__new__(GeminiClient)
    client.api_key = "test-key"
    client.model = "gemini-3.7-flash"
    client.config = RateLimitConfig(requests_per_minute=0, max_retries=4, base_backoff_seconds=0)
    client._sleep = lambda _s: None
    from scanner.core import RateLimiter

    client._limiter = RateLimiter(0, sleep=lambda _s: None)
    client._client = type("C", (), {"models": FakeModels()})()

    with pytest.raises(ScannerError, match="LLM request failed"):
        client.generate("sys", "user")
    assert FakeModels.calls == 1


def test_rate_limiter_sleeps_between_calls():
    from scanner.core import RateLimiter

    slept: list[float] = []
    limiter = RateLimiter(60, sleep=slept.append)
    limiter.acquire()
    limiter.acquire()
    assert len(slept) == 1
    assert slept[0] <= 1.0


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def _report_with_finding(tmp_path: Path) -> ScanReport:
    (tmp_path / "a.py").write_text("x = 1\n")
    client = FakeClient(json.dumps({"vulnerabilities": [_finding(severity="CRITICAL")]}))
    return Scanner(client).scan(tmp_path)


def test_render_json_roundtrips(tmp_path: Path):
    report = _report_with_finding(tmp_path)
    data = json.loads(render_json(report))
    assert data["summary"]["total_findings"] == 1
    assert data["results"][0]["vulnerabilities"][0]["cwe_id"] == "CWE-89"


def test_render_markdown_contains_sections(tmp_path: Path):
    md = render_markdown(_report_with_finding(tmp_path))
    assert "# Security Scan Report" in md
    assert "## Summary" in md
    assert "CWE-89" in md
    assert "**Secure replacement**" in md


def test_render_markdown_clean_scan(tmp_path: Path):
    (tmp_path / "safe.py").write_text("x = 1\n")
    report = Scanner(FakeClient(json.dumps({"vulnerabilities": []}))).scan(tmp_path)
    assert "No vulnerabilities found" in render_markdown(report)


def test_render_markdown_includes_truncation_warning():
    report = ScanReport(
        truncated=True,
        truncation_reason="Stopped after 1 of 3 files (2 not attempted): boom",
    )
    md = render_markdown(report)
    assert "Scan incomplete" in md
    assert "Stopped after 1 of 3" in md


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("18-20", {"startLine": 18, "endLine": 20}),
        ("18", {"startLine": 18}),
        ("18,25", {"startLine": 18, "endLine": 25}),
        ("251,258", {"startLine": 251, "endLine": 258}),
        ("unknown", None),
        ("", None),
    ],
)
def test_parse_line_region(raw, expected):
    assert _parse_line_region(raw) == expected


def test_render_sarif_structure(tmp_path: Path):
    report = _report_with_finding(tmp_path)
    sarif = json.loads(render_sarif(report))

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "llm-appsec-scanner"

    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "CWE-89"
    assert rules[0]["properties"]["security-severity"] == "9.5"  # CRITICAL
    assert rules[0]["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"

    results = run["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CWE-89"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.py"
    assert results[0]["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 18,
        "endLine": 20,
    }
    assert "llmAppsecScannerFingerprint/v1" in results[0]["partialFingerprints"]

    assert run["invocations"][0]["executionSuccessful"] is True


def test_render_sarif_dedupes_rules_by_cwe():
    findings = [_finding(vid="SEC-001", line="10"), _finding(vid="SEC-002", line="50")]
    report = ScanReport()
    report.results = [
        FileScanResult(
            file_path="a.py",
            vulnerabilities=[Vulnerability.model_validate(f) for f in findings],
        )
    ]
    sarif = json.loads(render_sarif(report))

    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2
    assert {r["ruleIndex"] for r in sarif["runs"][0]["results"]} == {0}


def test_render_sarif_reflects_truncation():
    report = ScanReport(truncated=True, truncation_reason="Stopped after 1 of 3 files: boom")
    sarif = json.loads(render_sarif(report))
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert "Stopped after 1 of 3" in invocation["toolExecutionNotifications"][0]["message"]["text"]


def test_write_report_sarif_extension(tmp_path: Path):
    report = _report_with_finding(tmp_path)

    sarif_path = write_report(report, tmp_path / "out" / "results.sarif")
    sarif_json_path = write_report(report, tmp_path / "out" / "results.sarif.json")

    for path in (sarif_path, sarif_json_path):
        data = json.loads(path.read_text())
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"][0]["ruleId"] == "CWE-89"


def test_write_report_json_and_markdown(tmp_path: Path):
    report = _report_with_finding(tmp_path)

    json_path = write_report(report, tmp_path / "out" / "report.json")
    md_path = write_report(report, tmp_path / "out" / "report.md")

    assert json.loads(json_path.read_text())["tool"] == "llm-appsec-scanner"
    assert md_path.read_text().startswith("# Security Scan Report")


def test_write_report_rejects_unknown_format(tmp_path: Path):
    report = ScanReport()
    with pytest.raises(ValueError, match="Unsupported output format"):
        write_report(report, tmp_path / "report.txt")


def test_render_terminal_hides_suppressed_finding_detail():
    report = ScanReport()
    v = Vulnerability.model_validate(_finding())
    v.suppressed = True
    report.results = [FileScanResult(file_path="a.py", vulnerabilities=[v])]
    report.rebuild_summary()

    console = Console(record=True, width=120)
    render_terminal(report, console=console)
    output = console.export_text()

    assert "suppressed by baseline" in output
    assert "SQL Injection via Direct Parameter Concatenation" not in output


# --------------------------------------------------------------------------
# baseline
# --------------------------------------------------------------------------


def _vuln(cwe: str = "CWE-89", file_path: str = "a.py", line: str = "18-20", title: str = "SQLi") -> Vulnerability:
    data = _finding(line=line)
    data["cwe_id"] = cwe
    data["file_path"] = file_path
    data["title"] = title
    return Vulnerability.model_validate(data)


def test_load_baseline_missing_file_is_empty(tmp_path: Path):
    baseline = load_baseline(tmp_path / "nonexistent.json")
    assert baseline.entries == []


def test_save_and_load_baseline_roundtrip(tmp_path: Path):
    path = tmp_path / "baseline.json"
    original = Baseline(
        entries=[BaselineEntry(file_path="a.py", cwe_id="CWE-89", line_start=18, line_end=20)]
    )
    save_baseline(original, path)
    loaded = load_baseline(path)
    assert loaded.entries[0].file_path == "a.py"
    assert loaded.entries[0].cwe_id == "CWE-89"


def test_apply_baseline_suppresses_exact_match():
    baseline = Baseline(
        entries=[BaselineEntry(file_path="a.py", cwe_id="CWE-89", line_start=18, line_end=20)]
    )
    report = ScanReport(results=[FileScanResult(file_path="a.py", vulnerabilities=[_vuln()])])

    suppressed_count = apply_baseline(report, baseline)
    report.rebuild_summary()

    assert suppressed_count == 1
    assert report.findings[0].suppressed is True
    assert report.summary.total_findings == 0
    assert report.summary.suppressed_findings == 1
    assert report.has_actionable_findings is False


def test_apply_baseline_matches_despite_reworded_title():
    """The whole point: a baseline must keep suppressing a finding even if
    the model reworded its title on a later run, as observed in practice."""
    baseline = Baseline(
        entries=[
            BaselineEntry(
                file_path="a.py",
                cwe_id="CWE-89",
                line_start=18,
                line_end=20,
                title_at_acceptance="Original title from first run",
            )
        ]
    )
    reworded = _vuln(title="A completely different way of describing the same bug")
    report = ScanReport(results=[FileScanResult(file_path="a.py", vulnerabilities=[reworded])])

    apply_baseline(report, baseline)
    assert report.findings[0].suppressed is True


@pytest.mark.parametrize("line", ["18-20", "16-17", "21-22", "18", "20,21"])
def test_apply_baseline_tolerates_small_line_drift(line):
    baseline = Baseline(
        entries=[BaselineEntry(file_path="a.py", cwe_id="CWE-89", line_start=18, line_end=20)]
    )
    report = ScanReport(
        results=[FileScanResult(file_path="a.py", vulnerabilities=[_vuln(line=line)])]
    )
    apply_baseline(report, baseline)
    assert report.findings[0].suppressed is True, f"line={line!r} should be within tolerance"


def test_apply_baseline_does_not_match_far_away_line():
    baseline = Baseline(
        entries=[BaselineEntry(file_path="a.py", cwe_id="CWE-89", line_start=18, line_end=20)]
    )
    report = ScanReport(
        results=[FileScanResult(file_path="a.py", vulnerabilities=[_vuln(line="200-205")])]
    )
    apply_baseline(report, baseline)
    assert report.findings[0].suppressed is False


def test_apply_baseline_requires_matching_cwe():
    baseline = Baseline(
        entries=[BaselineEntry(file_path="a.py", cwe_id="CWE-89", line_start=18, line_end=20)]
    )
    report = ScanReport(
        results=[FileScanResult(file_path="a.py", vulnerabilities=[_vuln(cwe="CWE-798")])]
    )
    apply_baseline(report, baseline)
    assert report.findings[0].suppressed is False


def test_apply_baseline_requires_matching_file():
    baseline = Baseline(
        entries=[BaselineEntry(file_path="a.py", cwe_id="CWE-89", line_start=18, line_end=20)]
    )
    report = ScanReport(
        results=[FileScanResult(file_path="b.py", vulnerabilities=[_vuln(file_path="b.py")])]
    )
    apply_baseline(report, baseline)
    assert report.findings[0].suppressed is False


def test_update_baseline_adds_new_entries():
    result = merge_baseline(Baseline(), [_vuln()])
    assert len(result.entries) == 1
    assert result.entries[0].file_path == "a.py"
    assert result.entries[0].cwe_id == "CWE-89"
    assert result.entries[0].line_start == 18
    assert result.entries[0].line_end == 20


def test_update_baseline_is_idempotent():
    once = merge_baseline(Baseline(), [_vuln()])
    twice = merge_baseline(once, [_vuln()])
    assert len(twice.entries) == 1  # re-running against unchanged code doesn't grow the file


def test_update_baseline_preserves_existing_entries():
    existing = Baseline(
        entries=[BaselineEntry(file_path="old.py", cwe_id="CWE-798", line_start=1, line_end=2)]
    )
    result = merge_baseline(existing, [_vuln()])
    assert len(result.entries) == 2


def test_render_markdown_separates_suppressed_findings():
    active = _vuln(title="Still open")
    suppressed = _vuln(cwe="CWE-798", title="Accepted risk")
    suppressed.suppressed = True
    report = ScanReport(
        results=[FileScanResult(file_path="a.py", vulnerabilities=[active, suppressed])]
    )
    report.rebuild_summary()

    md = render_markdown(report)
    assert "## Suppressed by Baseline" in md
    assert "Accepted risk" in md
    assert "Still open" in md
    # Suppressed findings appear only in the compact list, not with full patch detail.
    assert md.count("**Secure replacement**") == 1


def test_render_sarif_marks_suppressed_results():
    active = _vuln(title="Still open")
    suppressed = _vuln(cwe="CWE-798", title="Accepted risk")
    suppressed.suppressed = True
    report = ScanReport(
        results=[FileScanResult(file_path="a.py", vulnerabilities=[active, suppressed])]
    )

    sarif = json.loads(render_sarif(report))
    suppressed_result = next(
        r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CWE-798"
    )
    active_result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CWE-89")

    assert "suppressions" in suppressed_result
    assert "suppressions" not in active_result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_cli_exits_1_on_findings(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding(severity="HIGH")]})),
    )

    result = CliRunner().invoke(cli_module.main, ["--target", str(tmp_path)])
    assert result.exit_code == 1


def test_cli_exits_0_when_clean(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": []})),
    )

    result = CliRunner().invoke(cli_module.main, ["--target", str(tmp_path)])
    assert result.exit_code == 0


def test_cli_no_fail_flag_forces_exit_0(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding()]})),
    )

    result = CliRunner().invoke(cli_module.main, ["--target", str(tmp_path), "--no-fail"])
    assert result.exit_code == 0


def test_cli_threshold_suppresses_low_findings(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding(severity="LOW")]})),
    )

    result = CliRunner().invoke(
        cli_module.main, ["--target", str(tmp_path), "--severity-threshold", "HIGH"]
    )
    assert result.exit_code == 0


def test_cli_missing_api_key_exits_2(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(cli_module, "load_dotenv", lambda *a, **k: None)

    result = CliRunner().invoke(cli_module.main, ["--target", str(tmp_path)])
    assert result.exit_code == 2


def test_cli_rejects_bad_output_extension(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    result = CliRunner().invoke(
        cli_module.main, ["--target", str(tmp_path), "--output", str(tmp_path / "r.txt")]
    )
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "flag, env, expected",
    [
        (["--model", "explicit-model"], "env-model", "explicit-model"),
        ([], "env-model", "env-model"),
        ([], None, "gemini-3.7-flash"),
    ],
    ids=["flag wins", "env used when no flag", "built-in default"],
)
def test_cli_model_precedence(tmp_path: Path, monkeypatch, flag, env, expected):
    """--model beats $LLM_APPSEC_MODEL beats DEFAULT_MODEL."""
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(cli_module, "load_dotenv", lambda *a, **k: None)
    if env:
        monkeypatch.setenv("LLM_APPSEC_MODEL", env)
    else:
        monkeypatch.delenv("LLM_APPSEC_MODEL", raising=False)

    seen: dict[str, str] = {}

    def fake_client(**kwargs):
        seen["model"] = kwargs["model"]
        return FakeClient(json.dumps({"vulnerabilities": []}))

    monkeypatch.setattr(cli_module, "GeminiClient", fake_client)

    CliRunner().invoke(cli_module.main, ["--target", str(tmp_path), *flag])
    assert seen["model"] == expected


def test_cli_writes_output_file(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    out = tmp_path / "report.json"

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding()]})),
    )

    CliRunner().invoke(cli_module.main, ["--target", str(src), "--output", str(out)])
    assert json.loads(out.read_text())["summary"]["total_findings"] == 1


def test_cli_writes_sarif_output(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    out = tmp_path / "results.sarif"

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding()]})),
    )

    result = CliRunner().invoke(cli_module.main, ["--target", str(src), "--output", str(out)])
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "CWE-89"
    assert result.exit_code == 1  # findings still gate the build normally


def test_cli_update_baseline_requires_baseline_flag(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    result = CliRunner().invoke(
        cli_module.main, ["--target", str(tmp_path), "--update-baseline"]
    )
    assert result.exit_code == 2


def test_cli_update_baseline_creates_file_and_exits_clean(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    baseline_path = tmp_path / "baseline.json"

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding(severity="CRITICAL")]})),
    )

    result = CliRunner().invoke(
        cli_module.main,
        ["--target", str(src), "--baseline", str(baseline_path), "--update-baseline"],
    )
    assert result.exit_code == 0  # accepting current state must not fail the build
    assert baseline_path.exists()
    saved = json.loads(baseline_path.read_text())
    assert len(saved["entries"]) == 1
    assert saved["entries"][0]["cwe_id"] == "CWE-89"


def test_cli_baseline_suppresses_previously_accepted_finding(tmp_path: Path, monkeypatch):
    """The end-to-end workflow: --update-baseline once, then --baseline on a
    later run with the same finding (even reworded) exits clean."""
    from click.testing import CliRunner

    from scanner import cli as cli_module

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    baseline_path = tmp_path / "baseline.json"

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding(severity="CRITICAL")]})),
    )
    CliRunner().invoke(
        cli_module.main,
        ["--target", str(src), "--baseline", str(baseline_path), "--update-baseline"],
    )

    reworded = _finding(severity="CRITICAL")
    reworded["title"] = "A totally reworded description of the same bug"
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [reworded]})),
    )
    result = CliRunner().invoke(
        cli_module.main, ["--target", str(src), "--baseline", str(baseline_path)]
    )
    assert result.exit_code == 0


def test_cli_baseline_still_fails_on_genuinely_new_finding(tmp_path: Path, monkeypatch):
    from click.testing import CliRunner

    from scanner import cli as cli_module

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    baseline_path = tmp_path / "baseline.json"
    save_baseline(
        Baseline(
            entries=[
                BaselineEntry(file_path="a.py", cwe_id="CWE-798", line_start=1, line_end=2)
            ]
        ),
        baseline_path,
    )

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        cli_module,
        "GeminiClient",
        lambda **kw: FakeClient(json.dumps({"vulnerabilities": [_finding(severity="CRITICAL")]})),
    )
    result = CliRunner().invoke(
        cli_module.main, ["--target", str(src), "--baseline", str(baseline_path)]
    )
    assert result.exit_code == 1  # different CWE at a different line: not the accepted finding


def test_cli_exits_2_when_truncated_even_with_findings(tmp_path: Path, monkeypatch):
    """An incomplete scan must never look like a passing (0) or even a normal
    failing (1) run — CI should treat it as untrustworthy, not as a clean bill
    of health for the files it never got to."""
    from click.testing import CliRunner

    from scanner import cli as cli_module

    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    client = QuotaExhaustedClient(
        responses=[json.dumps({"vulnerabilities": [_finding(severity="CRITICAL")]})],
        fail_after=1,
    )
    monkeypatch.setattr(cli_module, "GeminiClient", lambda **kw: client)

    result = CliRunner().invoke(cli_module.main, ["--target", str(tmp_path)])
    assert result.exit_code == 2
