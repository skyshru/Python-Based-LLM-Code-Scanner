"""Restrict a scan to files changed since a git ref.

A PR only needs its own diff reviewed, not the whole repository. Pairing
this with the response cache means an unchanged file costs nothing even
when it *is* discovered, and with this it is not discovered at all.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(Exception):
    """Git is unavailable, the target is not a repo, or the ref is unknown."""


def _run_git(args: list[str], cwd: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:  # git not installed
        raise GitError("git executable not found on PATH") from exc

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip()
        raise GitError(message or f"git {' '.join(args)} failed")
    return completed.stdout


def repository_root(target: Path) -> Path:
    """Locate the repo containing `target`, which may be a file or directory."""
    start = target if target.is_dir() else target.parent
    output = _run_git(["rev-parse", "--show-toplevel"], cwd=start)
    return Path(output.strip()).resolve()


def changed_files(
    target: Path,
    ref: str,
    include_untracked: bool = True,
) -> set[Path]:
    """Absolute paths of files that differ from `ref` and still exist.

    Untracked files are included by default: a brand-new file is exactly
    the kind of code a PR scan must not miss, and git does not report it
    as a diff against any ref.

    Deleted paths are dropped -- git lists them as changed, but there is
    nothing left to scan.
    """
    target = Path(target).resolve()
    root = repository_root(target)

    names = _run_git(["diff", "--name-only", ref], cwd=root).splitlines()
    if include_untracked:
        names += _run_git(
            ["ls-files", "--others", "--exclude-standard"], cwd=root
        ).splitlines()

    changed: set[Path] = set()
    for name in names:
        name = name.strip()
        if not name:
            continue
        path = (root / name).resolve()
        if path.is_file():
            changed.add(path)
    return changed
