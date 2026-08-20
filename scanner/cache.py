"""Content-addressed cache for LLM responses.

A scan re-run over mostly-unchanged code should not re-pay for every file.
`CachingClient` decorates any `LLMClient` and memoizes responses on disk,
keyed by a hash of everything that can change the answer.

Deliberately a decorator over the `LLMClient` protocol rather than logic
inside `GeminiClient`: `Scanner` needs no changes, tests can wrap a fake,
and a future non-Gemini backend inherits caching for free.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .core import LLMClient

DEFAULT_CACHE_DIR = ".llm-appsec-cache"

# Bumped only if the on-disk record shape changes in a way older entries
# cannot satisfy. It is part of the key, so a bump invalidates everything
# rather than risking a stale read against a new format.
CACHE_FORMAT_VERSION = 1


@dataclass
class CacheStats:
    """Per-run counters, surfaced by the CLI so quota saved is visible.

    Guarded by a lock: `+= 1` is not atomic, so concurrent workers would
    silently undercount without one.
    """

    hits: int = 0
    misses: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_hit(self) -> None:
        with self._lock:
            self.hits += 1

    def record_miss(self) -> None:
        with self._lock:
            self.misses += 1

    @property
    def total(self) -> int:
        return self.hits + self.misses


class ResponseCache:
    """Plain key -> response store, one JSON file per entry."""

    def __init__(self, cache_dir: str | Path):
        self.cache_dir = Path(cache_dir)

    def key_for(self, model: str, system_prompt: str, user_prompt: str) -> str:
        """Hash every input that can change the answer.

        `user_prompt` already encodes the file path, language, chunk
        boundaries and the numbered source itself, so hashing it covers
        content and chunking changes. `system_prompt` is included so that
        tuning the prompt invalidates the cache instead of silently
        serving results produced under the old rules -- a real hazard,
        given the prompt has already been retuned once mid-project.
        `model` is included because the same prompts demonstrably produce
        different findings on different models.
        """
        basis = "\0".join(
            [str(CACHE_FORMAT_VERSION), model, system_prompt, user_prompt]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def _path_for(self, key: str) -> Path:
        # Shard on the first two chars so a large repo does not produce a
        # single directory with thousands of entries.
        return self.cache_dir / key[:2] / f"{key}.json"

    def get(self, key: str) -> str | None:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            response = payload["response"]
        except (OSError, ValueError, KeyError):
            # A corrupt or truncated entry must degrade to a cache miss,
            # never break the scan.
            return None
        return response if isinstance(response, str) else None

    def put(self, key: str, response: str, model: str) -> None:
        path = self._path_for(key)
        record = {
            "key": key,
            "model": model,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "response": response,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write-then-rename so a reader never observes a half-written
            # entry. Two workers racing on the same key both write complete
            # temp files and one rename wins -- the contents are identical,
            # so either winner is correct.
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(record, handle, indent=2)
                os.replace(tmp, path)
            except BaseException:
                # Never leave a stray temp file behind on failure.
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError:
            # An unwritable cache is a missed optimization, not a failure.
            pass


class CachingClient:
    """Wraps an `LLMClient`, serving repeat prompts from disk."""

    def __init__(
        self,
        inner: LLMClient,
        model: str,
        cache_dir: str | Path = DEFAULT_CACHE_DIR,
    ):
        self.inner = inner
        self.model = model
        self.cache = ResponseCache(cache_dir)
        self.stats = CacheStats()

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        key = self.cache.key_for(self.model, system_prompt, user_prompt)

        cached = self.cache.get(key)
        if cached is not None:
            self.stats.record_hit()
            return cached

        self.stats.record_miss()
        # Only reached on a miss, and only cached on success: an exception
        # propagates uncached, so a quota failure or a malformed response
        # is never memoized as if it were a real answer.
        response = self.inner.generate(system_prompt, user_prompt)
        self.cache.put(key, response, self.model)
        return response
