# Build Flow & Developer Manual — llm-appsec-scanner

A module-by-module walkthrough of what was built, why, and how the pieces fit together. Read it top to bottom the first time; after that, use it as a reference — each module is self-contained.

**Contents**

- [Module 0 — Orientation](#module-0--orientation)
- [Module 1 — Project Scaffolding](#module-1--project-scaffolding)
- [Module 2 — The Data Model](#module-2--the-data-model)
- [Module 3 — File Discovery & Chunking](#module-3--file-discovery--chunking)
- [Module 4 — The LLM Core](#module-4--the-llm-core)
- [Module 4a — Concurrency](#module-4a--concurrency)
- [Module 5 — Reporting](#module-5--reporting)
- [Module 5a — Baseline Suppression](#module-5a--baseline-suppression)
- [Module 5b — Response Caching](#module-5b--response-caching)
- [Module 6 — The CLI](#module-6--the-cli)
- [Module 7 — Testing](#module-7--testing)
- [Module 8 — End-to-End Trace](#module-8--end-to-end-trace)
- [Appendix A — Extending the Scanner](#appendix-a--extending-the-scanner)
- [Appendix B — Troubleshooting](#appendix-b--troubleshooting)

---

## Module 0 — Orientation

### What this tool is

A command-line SAST scanner that uses an LLM instead of pattern rules. You point it at code; it points at vulnerabilities, with line numbers and patches.

### The build order and why

The modules were built inside-out, following the dependency graph:

```
1. models.py        ← nothing depends on it being finished, everything depends on its shape
2. file_handler.py  ← needs nothing from the LLM
3. core.py          ← needs models + file_handler
4. reporter.py      ← needs models only
5. cli.py           ← wires everything
6. tests/           ← written against the finished contracts
```

Starting at `models.py` means the *shape of a finding* is settled before any code depends on it. Every later module is written against a schema that already exists, so no module gets rewritten when the schema firms up.

### Repository layout

```
llm-appsec-scanner/
├── scanner/
│   ├── __init__.py        public exports + __version__
│   ├── cli.py             CLI entrypoint
│   ├── core.py            LLM orchestration
│   ├── models.py          Pydantic schemas
│   ├── file_handler.py    traversal, filtering, chunking
│   ├── reporter.py        JSON / Markdown / SARIF / terminal
│   ├── baseline.py        cross-run suppression of accepted findings
│   └── cache.py           content-addressed LLM response cache
├── tests/
│   ├── test_scanner.py    140 tests, no network
│   └── vulnerable_samples/
├── docs/
│   ├── DESIGN.md          architecture and rationale
│   ├── FLOW.md            this file
│   └── PHASES.md          delivery log
├── .env.example
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Module 1 — Project Scaffolding

**Files:** `pyproject.toml`, `requirements.txt`, `.env.example`, `.gitignore`

### Dependencies and why each is there

| Package | Role | Why this one |
| --- | --- | --- |
| `google-genai` | Gemini SDK | The current official SDK; supports `response_schema` structured output |
| `pydantic>=2.6` | Schema + validation | v2 validators normalize the variation LLMs produce |
| `click>=8.1` | CLI | Declarative options, and `CliRunner` makes the CLI testable |
| `rich>=13.7` | Terminal output | Tables, panels, syntax highlighting for patches |
| `python-dotenv` | `.env` loading | Keeps the API key out of shell history and source control |

### The console entrypoint

```toml
[project.scripts]
llm-appsec-scanner = "scanner.cli:main"
```

After `pip install -e .`, `llm-appsec-scanner` is on `PATH`. This matters for CI: pipeline YAML calls a binary name, not `python -m`.

### Secret hygiene

`.env` is gitignored; `.env.example` is committed with placeholder values. This is the standard pattern — a new contributor copies the example, and the real key can never be committed by accident.

---

## Module 2 — The Data Model

**File:** [`scanner/models.py`](../scanner/models.py)

Everything else in the codebase is shaped by this file.

### 2.1 `Severity` — an ordered string enum

```python
class Severity(str, Enum):
    LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int: return _SEVERITY_RANK[self]
    def __ge__(self, other): return self.rank >= other.rank
```

Subclassing `str` keeps it human-readable in JSON. The comparison dunders let threshold filtering read as `finding.severity >= threshold`, so the ordering is defined once and used everywhere — filtering, sorting, and report ordering all share it.

### 2.2 `CodePatch` — the fix is mandatory

```python
class CodePatch(BaseModel):
    vulnerable_code: str
    fixed_code: str
    explanation: str = ""
```

`vulnerable_code` must be verbatim from the input (enforced by prompt rule 4), which makes findings verifiable: if the snippet is not in the file, the finding is a hallucination and can be discarded mechanically.

### 2.3 `Vulnerability` — the core record

The interesting parts are the normalizing validators.

**Line ranges.** Models return `"42"`, `42`, `[42, 57]`, or `(42, 57)` depending on mood. Rather than fighting it, the validator absorbs all four:

```python
@field_validator("line_number_range", mode="before")
@classmethod
def _normalize_line_range(cls, value):
    if isinstance(value, (list, tuple)):
        parts = [str(p) for p in value if p is not None]
        return parts[0] if len(parts) == 1 else f"{parts[0]}-{parts[-1]}"
    return str(value)
```

`mode="before"` runs the coercion *before* type checking, which is what allows a list to satisfy a `str` field.

**CWE ids.** A bare `"89"` becomes `"CWE-89"`. Small, but it means report grouping and filtering by CWE work without downstream cleanup.

**`extra="ignore"`** on every model: an unexpected key from a future model version is dropped, not raised. Forward compatibility for free.

### 2.4 `ScanReport` — the top-level document

`rebuild_summary()` derives all counts from `results` rather than incrementing counters during the scan. One source of truth means the summary cannot drift from the findings — a class of bug that is otherwise very easy to introduce and very hard to notice.

```python
@property
def has_actionable_findings(self) -> bool:
    return self.summary.total_findings > 0
```

Threshold filtering already happened in `Scanner.scan_file()`, and baseline suppression (Module 5a) marks rather than removes, so `total_findings` counts `active_findings` — everything in the report *except* what a baseline accepted — not literally everything present. `findings` (all of it, suppressed included) stays available for a complete, auditable JSON record; `active_findings` is what the exit code and severity table actually read. The CLI's exit-code check is still one property read either way.

---

## Module 3 — File Discovery & Chunking

**File:** [`scanner/file_handler.py`](../scanner/file_handler.py)

Everything here is pure filesystem work — this module knows nothing about LLMs and is trivially testable.

### 3.1 Filtering: three layers

**Extension allowlist.** `SUPPORTED_EXTENSIONS` maps suffix → language name; the language is passed to the prompt and to the syntax highlighter.

**Directory denylist.** `IGNORED_DIRECTORIES` covers VCS metadata, dependency trees, build output and virtualenvs. Pruning happens in-place during the walk:

```python
dirs[:] = sorted(d for d in dirs if not is_ignored_directory(d))
```

Mutating `dirs` in place is what makes `os.walk` skip the subtree entirely rather than walking into `node_modules` and discarding results afterwards. On a real repo this is the difference between a fast scan and an unusable one. The `sorted()` call makes traversal order deterministic across platforms — which matters for reproducible reports.

**Filename denylist.** Lockfiles (`package-lock.json`, `go.sum`, …) have supported extensions but contain no logic to analyze.

**Generated-code detection.** `looks_generated()` adds a fourth layer, and it is the one that matters most on real repos. Two signals, cheapest first:

```python
GENERATED_FILENAME_SUFFIXES = (".pb.go", "_pb2.py", ".g.dart", ...)   # no file read
GENERATED_CONTENT_MARKERS   = ("code generated by", "@generated", ...)  # first 20 lines only
```

Machine-generated code is skipped by default because findings in it are unactionable (the next `protoc` run overwrites any fix) and, on a metered API, expensive. On Tesla's `vehicle-command`, 9 generated files were 45 of 161 requests — 28% of the scan across 8% of the files.

Only the first 20 lines are read: generators put their banner at the top, and scanning deeper starts matching ordinary prose *about* generated code. `discover_files_detailed()` returns `(handwritten, generated)` from a single walk so the CLI can report the skipped count without traversing twice.

Test files are **not** skipped, though they were another 23% of that repo's cost — test fixtures leak real credentials often enough that those findings are worth paying for. Generated code has no such upside.

### 3.2 Reading: fail fast, fail specifically

`read_source_file()` guards in order — cheapest check first:

1. **Size** — over 400 KB is a bundle or a blob; skip before reading.
2. **Empty** — nothing to analyze.
3. **Binary sniff** — a NUL byte in the first 8 KB. This is the same heuristic `git` uses; cheap and reliable.
4. **Decode** — UTF-8, falling back to latin-1 (which never fails, so legacy-encoded files are still scanned).

Each failure raises `UnreadableFileError` with a specific message that ends up in `FileScanResult.error` and in the report's skipped-files section. The user learns *why* a file was skipped, not just that it was.

### 3.3 Chunking with overlap

Files at or under 400 lines go through whole, flagged `is_whole_file=True` so the prompt omits segment framing.

Larger files are split into 400-line windows advancing by `step = chunk_lines - overlap` = 380 lines:

```
window 1: lines   1–400
window 2: lines 381–780   ← 20-line overlap
window 3: lines 761–1000
```

The overlap exists because a vulnerability spanning lines 395–405 would be cut in half by both windows without it. With overlap, window 2 contains it whole. The duplicates this creates are removed later by `_dedupe()`.

### 3.4 Gutter numbering

```python
def number_lines(content: str, start_line: int = 1) -> str:
    return "\n".join(f"{start_line + i:>5} | {line}"
                     for i, line in enumerate(content.splitlines()))
```

`start_line` is the chunk's absolute offset, so line 381 of the file is labelled `381` even though it is line 1 of the window. Without this, findings from chunk 2 onward point at the wrong place — and a finding with a wrong line number is worse than no finding, because it destroys trust in the whole report.

---

## Module 4 — The LLM Core

**File:** [`scanner/core.py`](../scanner/core.py)

### 4.1 The system prompt

The prompt is the security expertise of this tool. Its five load-bearing rules:

| Rule | Purpose |
| --- | --- |
| Explicit taxonomy (OWASP, secrets, IaC, crypto) | Raises recall on under-weighted categories |
| "Report ONLY vulnerabilities you can point to" | Primary anti-hallucination control |
| "Do not report style or performance issues" | Keeps the report credible — noise is what kills adoption |
| Concrete severity rubric | Makes severity comparable across files and runs |
| "An empty result is a correct and expected answer" | Models want to produce *something*; this is what makes clean files come back clean |

### 4.2 Two-layer output enforcement

**Layer 1 — provider-side.** `RESPONSE_SCHEMA` is passed as `response_schema` with `response_mime_type="application/json"`, constraining generation itself.

**Layer 2 — client-side.** `parse_llm_response()` assumes layer 1 might leak:

```
raw text
 ├─ strip ```json fences if present
 ├─ json.loads
 │   └─ on failure: slice from first "{" to last "}", retry
 ├─ if the result is a list → wrap as {"vulnerabilities": [...]}
 └─ LLMResponse.model_validate  → ScannerError on violation
```

Any failure raises `ScannerError`, which `scan_file()` catches per chunk. One bad response never aborts the scan.

### 4.3 Rate limiting

```python
class RateLimiter:
    def acquire(self):
        elapsed = time.monotonic() - self._last_call
        if elapsed < self._min_interval:
            self._sleep(self._min_interval - elapsed)
```

`time.monotonic()` rather than `time.time()` — wall-clock adjustments (NTP, DST) must not affect pacing. `sleep` is injected so tests verify pacing without actually sleeping.

### 4.4 Retry with jittered backoff

```python
delay = min(base * (2 ** attempt), max_backoff)
return delay + random.uniform(0, delay * 0.25)
```

Jitter prevents thundering-herd retries when several scans run concurrently in CI. Retryability is decided by substring match on the stringified exception (`429`, `quota`, `timeout`, `unavailable`, …), because `google-genai` raises different exception types across versions. A false-positive retry costs one wasted request; a false negative costs the whole scan.

### 4.5 `Scanner.scan_file()` — the post-processing pipeline

```python
findings = [f for f in findings if f.severity >= self.severity_threshold]
findings.sort(key=lambda f: (-f.severity.rank, f.line_number_range))
findings = _renumber(_dedupe(findings))
```

Order matters:

1. **Filter first** — no point sorting findings that get dropped.
2. **Sort by severity descending, then line** — the reader sees CRITICAL first.
3. **Dedupe** on `(cwe_id, line_number_range, title.lower())` — removes overlap-window duplicates.
4. **Renumber last** — after all removals, ids run `SEC-001, SEC-002, …` with no gaps. Renumbering before deduping would leave holes.

### 4.6 The `LLMClient` protocol

```python
class LLMClient(Protocol):
    def generate(self, system_prompt: str, user_prompt: str) -> str: ...
```

`Scanner` depends on this, not on `GeminiClient`. Consequences: the test suite needs no API key and no network; swapping providers touches one class; the orchestration logic is provider-agnostic.

---

## Module 4a — Concurrency

**Files:** [`scanner/core.py`](../scanner/core.py) — `Scanner.scan()` and `RateLimiter`

`Scanner.scan()` submits files to a `ThreadPoolExecutor` (default 4 workers). Threads rather than asyncio, because the SDK call is blocking I/O and threads keep `LLMClient` an ordinary synchronous protocol.

**One shared rate limiter.** Every worker calls the same `RateLimiter`, so `--rpm` stays the hard cap no matter how many workers run. Concurrency buys overlap of request *latency*, not extra request volume — which is why the speedup plateaus once the rate limit, rather than latency, becomes the binding constraint (measured numbers in [DESIGN.md 4.13](DESIGN.md#413-concurrent-scanning)).

**The rate limiter was rewritten before concurrency could be added.** The original compared against `_last_call` and then slept:

```python
elapsed = now - self._last_call
if elapsed < self._min_interval:
    self._sleep(self._min_interval - elapsed)   # every thread sleeps the SAME amount
self._last_call = time.monotonic()              # ...and only then updates
```

With one worker that is fine. With several, they all read the same `_last_call`, all compute the same wait, and all fire together. The replacement reserves a slot under a lock and waits outside it:

```python
with self._lock:
    slot = now if self._next_slot is None else max(now, self._next_slot)
    self._next_slot = slot + self._min_interval
    wait = slot - now
if wait > 0:
    self._sleep(wait)     # each thread waits for its OWN slot
```

The regression test asserts the eight waits are *distinct*. Against the old code all eight are identical — the precise signature of the bug.

**Determinism.** Workers write into a pre-sized list at their own index; the report is assembled by walking discovery order afterwards. A concurrent scan yields a byte-identical report to a serial one, which a test verifies directly.

**Quota fail-fast, restated for concurrency.** Serially, "stopped at file N" implies N+1.. were untouched. Concurrently there is no clean boundary — file 8 can finish after file 7 hits the quota. So an unfilled slot means *never attempted*, a `threading.Event` stops workers that have not started, and the truncation message reports counts rather than a position. Files that already completed keep their results; discarding them would waste quota already spent.

---

## Module 5 — Reporting

**File:** [`scanner/reporter.py`](../scanner/reporter.py)

Four renderers over the same `ScanReport`. Each is a pure function of the report — no I/O except `write_report()`.

| Renderer | Consumer | Notes |
| --- | --- | --- |
| `render_terminal` | Developer at a keyboard | `rich` tables, severity colours, side-by-side syntax-highlighted patches |
| `render_json` | CI, dashboards, other tools | `model_dump_json(indent=2)` — the Pydantic model *is* the schema |
| `render_markdown` | PR comments, tickets, audits | Summary tables + per-file findings with fenced code |
| `render_sarif` | GitHub Code Scanning, Azure DevOps, CI security dashboards | SARIF 2.1.0; see [DESIGN.md §4.10](DESIGN.md#410-sarif-output) for the rules-vs-results and severity-mapping rationale |

`write_report()` picks the renderer from the file suffix and rejects anything not `.json`, `.md`/`.markdown`, or `.sarif`/`.sarif.json`. `.sarif.json` is checked against the full filename, not just `Path.suffix` (which would only see `.json`). The CLI mirrors this exact check in `_has_supported_output_extension()` and validates it *before* constructing the client, so a typo cannot waste a scan's worth of quota.

`_LANGUAGE_LEXER` maps internal language names to Pygments lexers (`terraform` → `hcl`), used for both terminal highlighting and Markdown fence tags.

---

## Module 5a — Baseline Suppression

**File:** [`scanner/baseline.py`](../scanner/baseline.py)

A small, self-contained module with two Pydantic models and four functions — deliberately kept separate from `reporter.py` (it decides *which* findings count, not how to render them) and from `models.py` (it's policy over the data model, not the data model itself).

```
Baseline                     the whole file: version + list[BaselineEntry]
├── BaselineEntry            file_path, cwe_id, line_start, line_end, accepted_at, title_at_acceptance

load_baseline(path)          missing file → empty Baseline, not an error
save_baseline(baseline, path)

apply_baseline(report, baseline)     marks matching findings .suppressed = True, in place
update_baseline(existing, findings)  folds current findings into a Baseline, additively
```

**The match rule, precisely:** `file_path` and `cwe_id` exact, line range fuzzy (overlap or within `LINE_TOLERANCE = 3` lines). `title_at_acceptance` is stored for a human to read later but is never compared. See [DESIGN.md §4.11](DESIGN.md#411-baseline-suppression) for why — short version: real testing showed `cwe_id` stays stable across runs of a non-deterministic model while titles and finding counts don't, so matching on title would make the baseline silently stop working.

**`update_baseline()` is where the idempotency lives.** It checks each incoming finding against *existing* entries with the same tolerance-based comparison `apply_baseline()` uses, before appending — so running `--update-baseline` twice against unchanged code produces an identical file, not a growing one. This isn't a separate dedup step; it's the same matching logic reused, which is what keeps "what got written" and "what will later match" from drifting apart.

**Suppression is a mark, not a deletion.** `apply_baseline()` sets `Vulnerability.suppressed = True` on the `ScanReport` in place and returns a count; it does not remove anything from `FileScanResult.vulnerabilities`. This is what lets `render_json()` stay a complete record while `ScanReport.active_findings` (added alongside this feature) filters suppressed findings out for everything that drives the exit code.

**CLI wiring** (`scanner/cli.py`): `--update-baseline` requires `--baseline PATH` — validated up front, before the client is constructed, consistent with the existing `--output` extension check. When updating, every current finding is also marked suppressed on the in-memory report before rendering, so the run's own terminal/file output shows "0 outstanding" immediately rather than listing findings right after just accepting them, and `no_fail` is forced on since accepting the current state was the point of the run, not gating on it.

---

## Module 5b — Response Caching

**File:** [`scanner/cache.py`](../scanner/cache.py)

Re-scanning a repo where two files changed should not re-pay for the other forty. On a free-tier key capped at ~20 requests/day — where a single large file consumes several, because it is chunked — that is the difference between a usable tool and one you can run twice.

```
CachingClient(inner, model, cache_dir)     decorates any LLMClient
├── ResponseCache                          key -> response, one JSON file per entry
│   ├── key_for(model, system, user)       sha256 over everything that changes the answer
│   ├── get(key)                           corrupt/missing entry -> None (a miss)
│   └── put(key, response, model)          unwritable dir -> silently skipped
└── CacheStats                             hits / misses, surfaced by the CLI
```

**Why a decorator and not a change to `GeminiClient`.** `CachingClient` implements the same `generate(system_prompt, user_prompt) -> str` protocol from Module 4, so `Scanner` needed no changes at all and tests can wrap a fake. It also sits *outside* the rate limiter, which lives inside `GeminiClient` — so a cache hit costs neither quota nor the RPM pacing sleep. Embedding the cache inside `GeminiClient` would have made every hit wait out the rate-limit interval for nothing.

**What goes into the key**, and why each part is load-bearing:

| Component | Why |
| --- | --- |
| `user_prompt` | Already contains file path, language, chunk boundaries and the numbered source — so content edits *and* chunking changes are covered with no extra bookkeeping |
| `system_prompt` | The prompt was retuned mid-project. A cache blind to that would have served pre-tuning results while we believed we were measuring the new prompt — a real correctness bug, not a hypothetical |
| `model` | The same prompts produce measurably different findings on different models; that difference *is* the Phase 2 result |
| `CACHE_FORMAT_VERSION` | Bumping it invalidates every entry at once, rather than risking a stale read against a changed record shape |

**Failure handling is deliberately one-directional: a broken cache may never break a scan.** `put()` runs only after `inner.generate()` returns, so exceptions propagate uncached — a quota error or malformed response is never memoized as if it were an answer. A corrupt entry degrades to a miss. An unwritable directory is swallowed. The worst case is that caching does nothing, never that the scan fails.

**Gotcha worth knowing.** `--cache-dir` defaults to a *relative* path, so the cache lands beside wherever you run the tool. The test suite therefore runs each test in an isolated working directory via an autouse fixture — without it, two tests scanning identical trivial content generate identical keys and one test's findings leak into another's supposedly-clean scan. That is not hypothetical; it happened the first time this was wired up, and three CLI tests failed because of it.

---

## Module 6 — The CLI

**File:** [`scanner/cli.py`](../scanner/cli.py)

The CLI is deliberately thin: parse, validate, wire, delegate, choose an exit code.

### Startup order

```
load_dotenv()                    → .env into environment
parse threshold                  → Severity enum
validate --output extension      → fail fast, before spending quota
construct GeminiClient           → MissingAPIKeyError here means exit 2
construct Scanner
scan with progress callbacks
render terminal output
write report file if requested
choose exit code
```

### Progress callbacks

`Scanner.scan()` accepts `on_file_start` and `on_file_done`. The scanner reports progress; the CLI decides how to display it. This keeps `rich` out of `core.py` and means a library consumer can plug in their own progress handling.

### Exit codes

```python
EXIT_CLEAN = 0      # nothing at or above threshold
EXIT_FINDINGS = 1   # actionable findings — fails the CI job
EXIT_ERROR = 2      # tool failure: no key, bad target, bad output path
```

The `2`-vs-`1` split matters in CI: a pipeline can distinguish "the scanner found problems" (fix the code) from "the scanner broke" (fix the pipeline). `--no-fail` forces `0` for baselining an existing codebase.

`stderr` gets its own `Console` so error messages survive `| tee report.txt` and stay unstyled in log aggregators.

---

## Module 7 — Testing

**File:** [`tests/test_scanner.py`](../tests/test_scanner.py) — 140 tests, no network, no API key.

### The `FakeClient`

```python
class FakeClient:
    def __init__(self, responses): ...
    def generate(self, system_prompt, user_prompt) -> str:
        self.calls.append((system_prompt, user_prompt))
        ...
```

Satisfying the `LLMClient` protocol is the whole trick. A single string replays for every call; a list returns one response per call, which is how multi-file scans are tested.

### Coverage map

| Area | Representative tests |
| --- | --- |
| Filtering | ignored dirs pruned, lockfiles skipped, binaries/empty/oversized rejected |
| Chunking | single window under threshold, overlapping windows above, absolute gutter offsets |
| Models | severity ordering, `(10, 14)` → `"10-14"`, `"89"` → `"CWE-89"` |
| Parsing | plain / fenced / prose-wrapped / bare-array JSON, non-JSON, invalid enum |
| Prompting | path, language and numbered code present; segment marker only when chunked |
| Orchestration | threshold filtering, sort order, renumbering, dedupe, per-file error isolation |
| Transport | retry-then-succeed on `429`, give up on `400`, limiter sleeps once |
| Reporting | JSON round-trip, Markdown sections, clean-scan wording, format rejection |
| CLI | exit `0`/`1`/`2`, `--no-fail`, threshold suppression, file writing |

### Vulnerable samples

`tests/vulnerable_samples/` holds deliberately insecure files used as scanner *input*:

| File | Flaws |
| --- | --- |
| `sample_sqli.py` | SQLi via concatenation and f-string, command injection, path traversal, Flask debug mode |
| `sample_hardcoded_keys.py` | AWS/Stripe keys, DB URL with password, MD5 passwords, `verify=False`, `pickle.loads`, wildcard IAM |
| `sample_insecure_s3.tf` | Public S3 bucket, `0.0.0.0/0` on 22 and 5432, unencrypted publicly-accessible RDS, hardcoded password |

These are the fixtures for manual end-to-end verification against the real API. **Never** import or execute them.

### Running

```bash
pytest -q                 # full suite, ~5s
pytest -q -k reporter     # one area
pytest -q -x --ff         # stop at first failure, failed-first
```

---

## Module 8 — End-to-End Trace

Following `llm-appsec-scanner -t ./src -o report.md --severity-threshold HIGH`:

```
1  cli.main()
   ├─ load_dotenv()                        GEMINI_API_KEY → environment
   ├─ threshold = Severity.HIGH
   ├─ ".md" is valid                       fail-fast check passes
   ├─ GeminiClient(model="gemini-3.7-flash", RateLimitConfig(rpm=15, retries=4))
   └─ Scanner(client, threshold=HIGH)

2  Scanner.scan("./src")
   └─ discover_files()                     walk, prune ignored dirs, filter extensions
                                           → [src/api/auth.py, src/db.py, ...]

3  per file: read_source_file()            size → empty → binary → decode
   └─ SourceFile(relative_path="api/auth.py", language="python", content=...)

4  Scanner.scan_file(source)
   ├─ chunk_file()                         520 lines → 2 overlapping windows
   ├─ per chunk:
   │   ├─ build_user_prompt()              metadata + segment marker + gutter-numbered code
   │   ├─ limiter.acquire()                sleep to hold 15 rpm
   │   ├─ client.generate()                → raw JSON (retry on 429/5xx)
   │   └─ parse_llm_response()             fence strip → json.loads → Pydantic validate
   ├─ attach file_path to each finding
   ├─ drop findings below HIGH
   ├─ sort by (-severity, line)
   ├─ dedupe overlap duplicates
   └─ renumber SEC-001…                    → FileScanResult

5  report.rebuild_summary()                counts derived from results

6  render_terminal(report)                 summary table + per-finding panels

7  write_report(report, "report.md")       → render_markdown → disk

8  exit 1                                  findings exist at/above HIGH
```

---

## Appendix A — Extending the Scanner

### Add a language

1. Add the suffix to `SUPPORTED_EXTENSIONS` in `file_handler.py`.
2. Add the Pygments lexer to `_LANGUAGE_LEXER` in `reporter.py`.
3. Add a vulnerable sample under `tests/vulnerable_samples/`.

No other module changes — language is data, not logic.

### Add a finding field

1. Add the field to `Vulnerability` in `models.py` (give it a default for backward compatibility).
2. Add it to `RESPONSE_SCHEMA` in `core.py`, and to `required` only if the model can always produce it.
3. Mention it in `SYSTEM_PROMPT` if the model needs guidance.
4. Render it in `reporter.py`.

### Swap the LLM provider

Implement `generate(system_prompt, user_prompt) -> str` in a new class and pass it to `Scanner`. Nothing in `core.Scanner`, `models`, or `reporter` changes.

### Tune chunking

`DEFAULT_CHUNK_LINES` and `CHUNK_OVERLAP_LINES` in `file_handler.py`, or `--chunk-lines` at runtime. Smaller windows mean more requests but more focused analysis.

### Change the default model

`DEFAULT_MODEL` lives in `models.py` — the innermost module — and `core.py` re-exports it so the dependency direction stays `core → models`. At runtime the resolution order is:

```
--model flag  →  $LLM_APPSEC_MODEL  →  DEFAULT_MODEL
```

resolved in `cli.main()` *after* `load_dotenv()`, so `.env` can supply it. Google retires model ids periodically; to see what your key can currently reach:

```python
from google import genai
client = genai.Client(api_key=...)
for m in client.models.list():
    print(m.name, getattr(m, "supported_actions", None))
```

---

## Appendix B — Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `error: GEMINI_API_KEY is not set` | No key in environment or `.env` | `cp .env.example .env` and fill it in |
| `404 NOT_FOUND … model is no longer available` | Google retired the model id | Pick a current one: `--model gemini-3.7-flash`, or list what your key can reach (see below) |
| Key looks set but scanner says it isn't | `.env` edited but not saved, or the placeholder left in place | Save the file. Note `your-api-key-here` is *truthy*, so it passes the guard and fails later at the API |
| Scanner uses an unexpected model | `LLM_APPSEC_MODEL` in `.env` overriding the default | Precedence is `--model` → `$LLM_APPSEC_MODEL` → `DEFAULT_MODEL` |
| `LLM request failed: 429 …` after retries | Sustained per-minute rate limiting (not a daily cap) | Lower `--rpm`, raise `--max-retries`, or narrow `--target` |
| `scan incomplete: Stopped after N of M files …`, exit `2` | Daily API quota exhausted mid-scan | Wait for the provider's daily reset, switch `--model` to one with separate quota, or move to a paid tier. The scan stops immediately rather than retrying every remaining file — see [DESIGN.md §4.7a](DESIGN.md#47a-daily-quota-exhaustion-is-not-a-per-file-error) |
| `Model response did not contain JSON` | Model returned prose (rare with schema) | Usually transient; re-run. Persistent → check the model id |
| "No supported source files found" | Extensions unsupported, or everything filtered | Check `SUPPORTED_EXTENSIONS` and the ignore lists |
| Exit `1` on a clean-looking repo | Findings exist at/above threshold | Read the report; raise the threshold or use `--no-fail` |
| Exit `2` immediately | Missing key, bad target, bad `--output` extension, or a truncated (quota-exhausted) scan | Read the stderr message — a truncated scan always exits `2`, even if findings exist in the files that did complete |
| Scan is slow | Serial requests + RPM pacing | Narrow `--target`; concurrency is on the roadmap |
| Line numbers look wrong | Reporting bug on a chunked file | Confirm the file is >400 lines; check `number_lines` offsets |
| Progress lines appear out of order | Files are scanned in parallel (default 4 workers) | Expected. The *report* is always reassembled in discovery order; only live progress interleaves. `--concurrency 1` restores serial output |
| Raising `--concurrency` does not speed anything up | The `--rpm` cap is the binding limit, not request latency | Expected below ~4 workers on a free tier. Raise `--rpm` too, or accept the plateau — see [DESIGN.md 4.13](DESIGN.md#413-concurrent-scanning) |
| Fewer files scanned than expected | Generated files (protobuf stubs, codegen output) are skipped by default | Expected; the count is printed. `--include-generated` scans them |
| A file you consider hand-written was skipped | It matched a generated filename pattern, or has a `Code generated`/`@generated` banner in its first 20 lines | Scan it explicitly by path (always honoured), or pass `--include-generated` |
| Scan returns instantly with no API calls | Every chunk was served from the response cache | Expected after an unchanged re-run. `--no-cache` forces a fresh scan; the `cache: N hit(s)` line reports it |
| Results look stale after editing the system prompt | They are not — the prompt is part of the cache key, so tuning it invalidates every entry | If you suspect otherwise, confirm with `--no-cache`; a mismatch would be a bug worth reporting |
| Cache directory appearing in odd places | `--cache-dir` is relative by default, so it lands in the current working directory | Pass an absolute `--cache-dir`, or run from the repo root. It is gitignored and safe to delete |
| `error: --update-baseline requires --baseline PATH` | Passed `--update-baseline` alone | Add `--baseline PATH`; the two flags always go together |
| A finding that should be new got silently suppressed | Baseline's fuzzy line-range tolerance (`LINE_TOLERANCE = 3`) matched a *different* finding of the same CWE nearby | Known, accepted tradeoff — see [DESIGN.md §4.11](DESIGN.md#411-baseline-suppression). Remove the offending entry from the baseline file by hand if it's too coarse for that spot |
| A finding you expected to be suppressed still fails the build | `file_path` or `cwe_id` didn't match exactly (baseline never matches on title) | Confirm the baseline entry's `file_path`/`cwe_id` against the new finding; re-run `--update-baseline` to accept it if it's genuinely the same issue |
