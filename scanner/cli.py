"""CLI entrypoint for llm-appsec-scanner."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console

from .baseline import apply_baseline, load_baseline, save_baseline
from .baseline import update_baseline as merge_baseline
from .cache import DEFAULT_CACHE_DIR, CachingClient
from .core import (
    DEFAULT_CONCURRENCY,
    DEFAULT_MODEL,
    GeminiClient,
    RateLimitConfig,
    Scanner,
    ScannerError,
)
from .models import FileScanResult, Severity
from .reporter import render_terminal, write_report

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

console = Console()
err_console = Console(stderr=True)


def _has_supported_output_extension(path: Path) -> bool:
    """Mirrors reporter.write_report()'s format dispatch, checked up front so
    a bad --output extension fails before any API quota is spent."""
    name = path.name.lower()
    if name.endswith(".sarif.json") or path.suffix.lower() == ".sarif":
        return True
    return path.suffix.lower() in {".json", ".md", ".markdown"}


@click.command(name="llm-appsec-scanner")
@click.option(
    "--target",
    "-t",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="File or directory to scan.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Write the report to this path (.json, .md or .sarif).",
)
@click.option(
    "--severity-threshold",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default=Severity.LOW.value,
    show_default=True,
    help="Minimum severity to report and to fail the build on.",
)
@click.option(
    "--model",
    default=None,
    help=(
        "Gemini model id. Falls back to $LLM_APPSEC_MODEL, then "
        f"{DEFAULT_MODEL}."
    ),
)
@click.option(
    "--rpm",
    type=int,
    default=15,
    show_default=True,
    help="Client-side request-per-minute cap.",
)
@click.option(
    "--max-retries",
    type=int,
    default=4,
    show_default=True,
    help="Retries per request on quota or transient errors.",
)
@click.option(
    "--concurrency",
    type=int,
    default=DEFAULT_CONCURRENCY,
    show_default=True,
    help="Files scanned in parallel. Total request rate stays bounded by --rpm.",
)
@click.option(
    "--chunk-lines",
    type=int,
    default=None,
    help="Override the lines-per-request window for large files.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Print only the summary table, not every finding.",
)
@click.option(
    "--no-fail",
    is_flag=True,
    help="Always exit 0, even when findings exist.",
)
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_CACHE_DIR,
    show_default=True,
    help="Directory for cached LLM responses.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Bypass the response cache and re-query the model for every chunk.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Suppress findings already accepted in this baseline file.",
)
@click.option(
    "--update-baseline",
    is_flag=True,
    help=(
        "Instead of suppressing, fold every current finding into --baseline "
        "(creating it if needed) and don't fail the build."
    ),
)
@click.version_option(package_name="llm-appsec-scanner", prog_name="llm-appsec-scanner")
def main(
    target: Path,
    output: Path | None,
    severity_threshold: str,
    model: str | None,
    rpm: int,
    max_retries: int,
    concurrency: int,
    chunk_lines: int | None,
    quiet: bool,
    no_fail: bool,
    cache_dir: Path,
    no_cache: bool,
    baseline_path: Path | None,
    update_baseline: bool,
) -> None:
    """LLM-assisted SAST scanner for OWASP/CWE-aligned vulnerability detection."""
    load_dotenv()

    # Resolved after load_dotenv() so .env can supply the default: an explicit
    # --model wins, then $LLM_APPSEC_MODEL, then the built-in default.
    model = model or os.environ.get("LLM_APPSEC_MODEL") or DEFAULT_MODEL

    threshold = Severity(severity_threshold.upper())

    if output and not _has_supported_output_extension(output):
        err_console.print(
            f"[red]error:[/red] unsupported output format '{output.suffix}'. "
            "Use .json, .md or .sarif"
        )
        sys.exit(EXIT_ERROR)

    if update_baseline and not baseline_path:
        err_console.print("[red]error:[/red] --update-baseline requires --baseline PATH")
        sys.exit(EXIT_ERROR)

    try:
        client = GeminiClient(
            model=model,
            rate_limit=RateLimitConfig(requests_per_minute=rpm, max_retries=max_retries),
        )
    except ScannerError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        sys.exit(EXIT_ERROR)

    # Wrapping rather than modifying GeminiClient means the rate limiter,
    # which lives inside it, only paces actual network calls -- cache hits
    # cost neither quota nor pacing delay.
    caching_client = None if no_cache else CachingClient(client, model=model, cache_dir=cache_dir)

    scanner = Scanner(
        client=caching_client or client,
        model=model,
        severity_threshold=threshold,
        chunk_lines=chunk_lines,
        concurrency=concurrency,
    )

    def on_file_start(path: str, index: int, total: int) -> None:
        console.print(f"[dim]({index}/{total})[/dim] scanning [cyan]{path}[/cyan]")

    def on_file_done(result: FileScanResult) -> None:
        if result.error:
            console.print(f"  [yellow]skipped:[/yellow] {result.error}")
        elif result.vulnerabilities:
            console.print(f"  [red]{len(result.vulnerabilities)} finding(s)[/red]")

    try:
        report = scanner.scan(
            target,
            on_file_start=on_file_start,
            on_file_done=on_file_done,
        )
    except FileNotFoundError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        sys.exit(EXIT_ERROR)
    except ScannerError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]interrupted[/yellow]")
        sys.exit(EXIT_ERROR)

    if report.summary.files_discovered == 0:
        console.print("[yellow]No supported source files found under the target.[/yellow]")

    if caching_client and caching_client.stats.total:
        stats = caching_client.stats
        console.print(
            f"[dim]cache: {stats.hits} hit(s), {stats.misses} miss(es) "
            f"({cache_dir})[/dim]"
        )

    if baseline_path:
        existing_baseline = load_baseline(baseline_path)
        if update_baseline:
            merged = merge_baseline(existing_baseline, report.findings)
            save_baseline(merged, baseline_path)
            for finding in report.findings:
                finding.suppressed = True
            report.rebuild_summary(files_discovered=report.summary.files_discovered)
            console.print(
                f"[green]baseline updated:[/green] {baseline_path} "
                f"({len(merged.entries)} accepted findings)"
            )
            # The whole point of this run was to accept the current state,
            # not to gate on it.
            no_fail = True
        else:
            suppressed_count = apply_baseline(report, existing_baseline)
            if suppressed_count:
                report.rebuild_summary(files_discovered=report.summary.files_discovered)
                console.print(
                    f"[dim]{suppressed_count} finding(s) suppressed by baseline "
                    f"({baseline_path})[/dim]"
                )

    render_terminal(report, console=console, verbose=not quiet)

    if report.truncated:
        console.print(f"\n[bold red]scan incomplete:[/bold red] {report.truncation_reason}")

    if output:
        try:
            written = write_report(report, output)
        except (OSError, ValueError) as exc:
            err_console.print(f"[red]error:[/red] could not write report: {exc}")
            sys.exit(EXIT_ERROR)
        console.print(f"\n[green]report written:[/green] {written}")

    if report.truncated:
        # An incomplete scan must never report as clean or be silently
        # trusted by CI — surface it as a tool error regardless of whether
        # the files that WERE scanned had findings.
        sys.exit(EXIT_ERROR)
    if report.has_actionable_findings and not no_fail:
        sys.exit(EXIT_FINDINGS)
    sys.exit(EXIT_CLEAN)


if __name__ == "__main__":
    main()
