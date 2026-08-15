"""Report rendering: JSON, Markdown, SARIF and rich terminal output."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from .models import ScanReport, Severity, Vulnerability

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

# SARIF `level` has no direct severity equivalent; this mapping follows the
# convention used by other SARIF-producing SAST tools (e.g. CodeQL).
SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# GitHub Code Scanning reads `properties["security-severity"]` (a 0.0-10.0
# score, not the SARIF `level`) to choose the Critical/High/Medium/Low badge
# it displays. Values below are representative midpoints of GitHub's own
# documented bucket ranges.
SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
}

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

_LANGUAGE_LEXER = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "go": "go",
    "java": "java",
    "terraform": "hcl",
    "yaml": "yaml",
}


def render_json(report: ScanReport, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def render_markdown(report: ScanReport) -> str:
    summary = report.summary
    lines: list[str] = [
        "# Security Scan Report",
        "",
        f"- **Tool:** `{report.tool}` v{report.version}",
        f"- **Model:** `{report.model}`",
        f"- **Target:** `{report.target}`",
        f"- **Generated:** {report.generated_at.isoformat()}",
        f"- **Severity threshold:** {report.severity_threshold.value}",
        "",
    ]
    if report.truncated:
        lines += [
            f"> **⚠ Scan incomplete:** {report.truncation_reason}",
            "",
        ]
    lines += [
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Files discovered | {summary.files_discovered} |",
        f"| Files scanned | {summary.files_scanned} |",
        f"| Files failed | {summary.files_failed} |",
        f"| Total findings | {summary.total_findings} |",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity.value} | {summary.findings_by_severity.get(severity.value, 0)} |")

    lines += ["", "## Findings", ""]

    findings = report.findings
    if not findings:
        lines.append("No vulnerabilities found at or above the configured threshold.")
    else:
        for result in report.results:
            if not result.vulnerabilities:
                continue
            lines += [f"### `{result.file_path}`", ""]
            for finding in result.vulnerabilities:
                lines += _markdown_finding(finding, result.language)

    failed = [r for r in report.results if r.error]
    if failed:
        lines += ["## Skipped / Failed Files", ""]
        for result in failed:
            lines.append(f"- `{result.file_path}` — {result.error}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _parse_line_region(line_number_range: str) -> dict[str, int] | None:
    """Best-effort extraction of a SARIF region from our free-form line string.

    `line_number_range` is deliberately loose (a single line, a range, or a
    comma-separated list) since it comes straight from the model. SARIF wants
    integer start/end lines, so this takes the min and max of whatever digits
    are present and gives up cleanly if there are none.
    """
    numbers = [int(n) for n in re.findall(r"\d+", line_number_range)]
    if not numbers:
        return None
    start, end = min(numbers), max(numbers)
    region: dict[str, int] = {"startLine": start}
    if end != start:
        region["endLine"] = end
    return region


def _cwe_help_uri(cwe_id: str) -> str | None:
    match = re.search(r"(\d+)", cwe_id)
    if not match:
        return None
    return f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"


def _finding_fingerprint(finding: Vulnerability) -> str:
    """A stable-ish identity for a finding, independent of its `vulnerability_id`.

    Not a full solution to cross-run matching (the model can reword a title
    or reclassify a CWE between runs), but it lets GitHub Code Scanning track
    the "same" alert across commits when the file, CWE and title agree,
    rather than treating every run's SEC-00N as a brand new alert.
    """
    basis = f"{finding.file_path}|{finding.cwe_id}|{finding.title.lower()}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def render_sarif(report: ScanReport, indent: int = 2) -> str:
    """Render findings as SARIF 2.1.0, for GitHub Code Scanning and similar tools."""
    findings = report.findings

    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for finding in findings:
        if finding.cwe_id in rule_index:
            continue
        rule_index[finding.cwe_id] = len(rules)
        rule: dict = {
            "id": finding.cwe_id,
            "name": re.sub(r"[^A-Za-z0-9]", "", finding.title) or finding.cwe_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.remediation},
            "properties": {
                "tags": ["security", finding.owasp_category],
                "security-severity": SARIF_SECURITY_SEVERITY[finding.severity],
            },
        }
        help_uri = _cwe_help_uri(finding.cwe_id)
        if help_uri:
            rule["helpUri"] = help_uri
        rules.append(rule)

    results: list[dict] = []
    for finding in findings:
        physical_location: dict = {"artifactLocation": {"uri": finding.file_path}}
        region = _parse_line_region(finding.line_number_range)
        if region:
            physical_location["region"] = region

        results.append(
            {
                "ruleId": finding.cwe_id,
                "ruleIndex": rule_index[finding.cwe_id],
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": f"{finding.description}\n\nRemediation: {finding.remediation}"},
                "locations": [{"physicalLocation": physical_location}],
                "partialFingerprints": {
                    "llmAppsecScannerFingerprint/v1": _finding_fingerprint(finding),
                },
                "properties": {
                    "severity": finding.severity.value,
                    "vulnerabilityId": finding.vulnerability_id,
                },
            }
        )

    # A truncated (quota-exhausted) scan must not look like a completed,
    # clean run to GitHub Code Scanning either -- same principle as the exit
    # code always forcing 2 in cli.py.
    invocation: dict = {"executionSuccessful": not report.truncated}
    if report.truncated:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {"text": report.truncation_reason or "Scan stopped early."},
            }
        ]

    sarif = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "version": report.version,
                        "informationUri": "https://github.com/skyshru/Python-Based-LLM-Code-Scanner",
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=indent)


def _markdown_finding(finding: Vulnerability, language: str) -> list[str]:
    lexer = _LANGUAGE_LEXER.get(language, "")
    return [
        f"#### {finding.vulnerability_id} — {finding.title}",
        "",
        f"- **Severity:** `{finding.severity.value}`",
        f"- **CWE:** {finding.cwe_id}",
        f"- **OWASP:** {finding.owasp_category}",
        f"- **Location:** `{finding.file_path}:{finding.line_number_range}`",
        "",
        "**Description**",
        "",
        finding.description,
        "",
        "**Remediation**",
        "",
        finding.remediation,
        "",
        "**Vulnerable code**",
        "",
        f"```{lexer}",
        finding.code_patch.vulnerable_code,
        "```",
        "",
        "**Secure replacement**",
        "",
        f"```{lexer}",
        finding.code_patch.fixed_code,
        "```",
        "",
    ] + ([finding.code_patch.explanation, ""] if finding.code_patch.explanation else [])


def render_terminal(report: ScanReport, console: Console | None = None, verbose: bool = True) -> None:
    console = console or Console()

    console.print()
    console.print(
        Panel.fit(
            f"[bold]llm-appsec-scanner[/bold]  •  model [cyan]{report.model}[/cyan]\n"
            f"target [dim]{report.target}[/dim]",
            border_style="blue",
        )
    )

    table = Table(title="Findings by Severity", show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for severity in SEVERITY_ORDER:
        count = report.summary.findings_by_severity.get(severity.value, 0)
        table.add_row(
            f"[{SEVERITY_STYLE[severity]}] {severity.value} [/]",
            str(count),
        )
    console.print(table)

    console.print(
        f"[dim]{report.summary.files_scanned} scanned, "
        f"{report.summary.files_failed} failed, "
        f"{report.summary.total_findings} findings "
        f"(threshold {report.severity_threshold.value})[/dim]"
    )

    if not verbose:
        return

    for result in report.results:
        for finding in result.vulnerabilities:
            _print_finding(console, finding, result.language)

    for result in report.results:
        if result.error:
            console.print(f"[yellow]![/yellow] [dim]{result.file_path}[/dim] — {result.error}")


def _print_finding(console: Console, finding: Vulnerability, language: str) -> None:
    style = SEVERITY_STYLE[finding.severity]
    header = (
        f"[{style}] {finding.severity.value} [/] "
        f"[bold]{finding.vulnerability_id}[/bold]  {finding.title}"
    )
    meta = (
        f"[dim]{finding.file_path}:{finding.line_number_range}"
        f"  •  {finding.cwe_id}  •  {finding.owasp_category}[/dim]"
    )
    console.print()
    console.print(header)
    console.print(meta)
    console.print(f"\n{finding.description}\n")
    console.print(f"[bold]Remediation:[/bold] {finding.remediation}\n")

    lexer = _LANGUAGE_LEXER.get(language, "text")
    console.print(
        Panel(
            Syntax(finding.code_patch.vulnerable_code, lexer, theme="ansi_dark", word_wrap=True),
            title="[red]vulnerable[/red]",
            border_style="red",
        )
    )
    console.print(
        Panel(
            Syntax(finding.code_patch.fixed_code, lexer, theme="ansi_dark", word_wrap=True),
            title="[green]secure[/green]",
            border_style="green",
        )
    )


def write_report(report: ScanReport, output_path: str | Path) -> Path:
    """Write the report to disk, choosing the format from the file suffix."""
    path = Path(output_path)
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name.endswith(".sarif.json") or suffix == ".sarif":
        content = render_sarif(report)
    elif suffix == ".json":
        content = render_json(report)
    elif suffix in {".md", ".markdown"}:
        content = render_markdown(report)
    else:
        raise ValueError(
            f"Unsupported output format '{suffix or path.name}'. Use .json, .md or .sarif"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
