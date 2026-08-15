"""Report rendering: JSON, Markdown and rich terminal output."""

from __future__ import annotations

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
    suffix = path.suffix.lower()

    if suffix == ".json":
        content = render_json(report)
    elif suffix in {".md", ".markdown"}:
        content = render_markdown(report)
    else:
        raise ValueError(
            f"Unsupported output format '{suffix or path.name}'. Use .json or .md"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
