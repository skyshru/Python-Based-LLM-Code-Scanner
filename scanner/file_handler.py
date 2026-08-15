"""Directory traversal, filtering and chunking of source files."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

SUPPORTED_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
}

IGNORED_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".terraform",
        "__pycache__",
        "node_modules",
        "bower_components",
        "vendor",
        "dist",
        "build",
        "target",
        "out",
        ".venv",
        "venv",
        "env",
        "site-packages",
        "coverage",
        "htmlcov",
    }
)

IGNORED_FILENAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "go.sum",
        "composer.lock",
        "Cargo.lock",
        ".terraform.lock.hcl",
    }
)

# Files above this size are skipped outright; the LLM cannot use them well and
# they are almost always generated bundles or vendored blobs.
MAX_FILE_BYTES = 400_000

# Roughly 4 chars per token; keep each chunk comfortably inside the context
# window while leaving room for the system prompt and the JSON response.
DEFAULT_CHUNK_LINES = 400
CHUNK_OVERLAP_LINES = 20


@dataclass(frozen=True)
class SourceFile:
    """A file that passed filtering, with its decoded contents."""

    path: Path
    relative_path: str
    language: str
    content: str

    @property
    def line_count(self) -> int:
        return self.content.count("\n") + 1


@dataclass(frozen=True)
class CodeChunk:
    """A contiguous slice of a source file sent to the LLM as one request."""

    file: SourceFile
    start_line: int
    end_line: int
    content: str
    index: int
    total: int

    @property
    def is_whole_file(self) -> bool:
        return self.total == 1


class UnreadableFileError(Exception):
    """Raised when a candidate file cannot be decoded as text."""


def is_ignored_directory(name: str) -> bool:
    return name in IGNORED_DIRECTORIES or name.startswith(".")


def is_supported_file(path: Path) -> bool:
    if path.name in IGNORED_FILENAMES:
        return False
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def language_for(path: Path) -> str:
    return SUPPORTED_EXTENSIONS.get(path.suffix.lower(), "unknown")


def _looks_binary(raw: bytes) -> bool:
    return b"\x00" in raw[:8192]


def discover_files(target: Path) -> list[Path]:
    """Return every supported source file under `target` (file or directory)."""
    target = Path(target)
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    if target.is_file():
        return [target] if is_supported_file(target) else []

    found: list[Path] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if not is_ignored_directory(d))
        for name in sorted(files):
            candidate = Path(root) / name
            if is_supported_file(candidate):
                found.append(candidate)
    return found


def read_source_file(path: Path, base: Path | None = None) -> SourceFile:
    """Decode a file to text, raising `UnreadableFileError` when impossible."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise UnreadableFileError(f"Cannot stat file: {exc}") from exc

    if size > MAX_FILE_BYTES:
        raise UnreadableFileError(
            f"File is {size} bytes, above the {MAX_FILE_BYTES} byte limit"
        )
    if size == 0:
        raise UnreadableFileError("File is empty")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UnreadableFileError(f"Cannot read file: {exc}") from exc

    if _looks_binary(raw):
        raise UnreadableFileError("File appears to be binary")

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise UnreadableFileError(f"Cannot decode file as text: {exc}") from exc

    relative = _relative_display_path(path, base)
    return SourceFile(
        path=path,
        relative_path=relative,
        language=language_for(path),
        content=content,
    )


def _relative_display_path(path: Path, base: Path | None) -> str:
    if base is None:
        return path.as_posix()
    base = Path(base)
    root = base.parent if base.is_file() else base
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def chunk_file(
    source: SourceFile,
    chunk_lines: int = DEFAULT_CHUNK_LINES,
    overlap: int = CHUNK_OVERLAP_LINES,
) -> list[CodeChunk]:
    """Split a file into overlapping line windows.

    Overlap keeps a vulnerability that straddles a boundary visible in at least
    one chunk in full.
    """
    lines = source.content.splitlines()
    if not lines:
        return []

    if len(lines) <= chunk_lines:
        return [
            CodeChunk(
                file=source,
                start_line=1,
                end_line=len(lines),
                content=source.content,
                index=0,
                total=1,
            )
        ]

    step = max(1, chunk_lines - overlap)
    windows: list[tuple[int, int]] = []
    start = 0
    while start < len(lines):
        end = min(start + chunk_lines, len(lines))
        windows.append((start, end))
        if end == len(lines):
            break
        start += step

    return [
        CodeChunk(
            file=source,
            start_line=start + 1,
            end_line=end,
            content="\n".join(lines[start:end]),
            index=i,
            total=len(windows),
        )
        for i, (start, end) in enumerate(windows)
    ]


def iter_chunks(
    sources: list[SourceFile],
    chunk_lines: int = DEFAULT_CHUNK_LINES,
) -> Iterator[CodeChunk]:
    for source in sources:
        yield from chunk_file(source, chunk_lines=chunk_lines)


def number_lines(content: str, start_line: int = 1) -> str:
    """Prefix each line with its absolute line number for the prompt."""
    return "\n".join(
        f"{start_line + i:>5} | {line}"
        for i, line in enumerate(content.splitlines())
    )
