"""Cross-run suppression of previously-accepted findings.

A baseline entry identifies "the same" finding by file path and CWE id,
matched exactly, plus a fuzzy (tolerance-based) line range. Title is
deliberately never matched on: real-world testing showed the same
underlying issue can come back reworded between runs on a non-deterministic
model, while cwe_id stayed stable. See docs/DESIGN.md for the full
rationale.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .models import ScanReport, Vulnerability

# Findings within this many lines of a baseline entry are treated as the
# same location. Absorbs normal line drift from chunk-boundary overlap and
# minor model rewording, without being loose enough to paper over a
# genuinely different finding that happens to land nearby.
LINE_TOLERANCE = 3


class BaselineEntry(BaseModel):
    """One accepted finding: enough to re-identify it, not to re-render it."""

    model_config = ConfigDict(extra="ignore")

    file_path: str
    cwe_id: str
    line_start: int
    line_end: int
    accepted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    title_at_acceptance: str = Field(
        default="",
        description="Informational only -- never used for matching, since titles can be reworded between runs.",
    )


class Baseline(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version: int = 1
    entries: list[BaselineEntry] = Field(default_factory=list)


def load_baseline(path: str | Path) -> Baseline:
    """Load a baseline file, or return an empty one if it doesn't exist yet.

    A missing file is a normal state (nobody has run --update-baseline yet),
    not an error -- --baseline against a fresh path just suppresses nothing.
    """
    path = Path(path)
    if not path.exists():
        return Baseline()
    return Baseline.model_validate_json(path.read_text(encoding="utf-8"))


def save_baseline(baseline: Baseline, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")


def _line_span(finding: Vulnerability) -> tuple[int, int] | None:
    numbers = [int(n) for n in re.findall(r"\d+", finding.line_number_range)]
    if not numbers:
        return None
    return min(numbers), max(numbers)


def _matches(entry: BaselineEntry, finding: Vulnerability) -> bool:
    if entry.file_path != finding.file_path or entry.cwe_id != finding.cwe_id:
        return False
    span = _line_span(finding)
    if span is None:
        return False
    start, end = span
    return not (end < entry.line_start - LINE_TOLERANCE or start > entry.line_end + LINE_TOLERANCE)


def apply_baseline(report: ScanReport, baseline: Baseline) -> int:
    """Mark findings that match a baseline entry as suppressed, in place.

    Returns the number of findings newly suppressed. Call
    report.rebuild_summary() afterwards to fold the change into the summary.
    """
    suppressed = 0
    for result in report.results:
        for finding in result.vulnerabilities:
            if finding.suppressed:
                continue
            if any(_matches(entry, finding) for entry in baseline.entries):
                finding.suppressed = True
                suppressed += 1
    return suppressed


def update_baseline(existing: Baseline, findings: list[Vulnerability]) -> Baseline:
    """Fold every current finding into the baseline (the --update-baseline path).

    Idempotent: re-running against unchanged code does not grow the file,
    since findings that already have an equivalent entry are skipped.
    """
    entries = list(existing.entries)
    for finding in findings:
        span = _line_span(finding)
        if span is None:
            continue
        start, end = span
        already_present = any(
            entry.file_path == finding.file_path
            and entry.cwe_id == finding.cwe_id
            and abs(entry.line_start - start) <= LINE_TOLERANCE
            and abs(entry.line_end - end) <= LINE_TOLERANCE
            for entry in entries
        )
        if already_present:
            continue
        entries.append(
            BaselineEntry(
                file_path=finding.file_path,
                cwe_id=finding.cwe_id,
                line_start=start,
                line_end=end,
                title_at_acceptance=finding.title,
            )
        )
    return Baseline(version=existing.version, entries=entries)
