# Design Document — llm-appsec-scanner

**Status:** Living document · updated as the system evolves
**Last updated:** Phase 1 (2026-08-15)

---

## 1. Problem Statement

Static analysis tools that work by pattern matching have a structural ceiling. A regex or an AST rule can find `eval(user_input)`, but it cannot tell you that a handler forgot to check whether the requesting user owns the record it is about to return. The flaws that cause real breaches — broken access control, insecure design, business-logic bypasses — are exactly the ones rule engines are worst at.

At the same time, rule engines produce enough noise that teams stop reading the output. The signal-to-noise ratio, not the detection rate, is usually what kills a SAST rollout.

**Goal:** build a scanner that reasons about code the way a security engineer does, emits findings that are specific enough to act on immediately (exact lines, working patch), and returns a machine-readable verdict that a CI pipeline can gate on.

**Non-goals for v0.1:**
- Replacing Semgrep/Bandit/tfsec. This is complementary.
- Cross-file dataflow analysis.
- Runtime/DAST testing.

---

## 2. Design Principles

| # | Principle | Consequence in the code |
| --- | --- | --- |
| 1 | **Structured output over prose** | Gemini `response_schema` + Pydantic v2. Free-text LLM output is unusable in a pipeline. |
| 2 | **Fail loudly on the tool, quietly on the file** | A missing API key is fatal (exit 2). One unparseable file is recorded and the scan continues. |
| 3 | **Every finding must be actionable** | `code_patch` is mandatory in the schema — a finding without a fix is a ticket nobody closes. |
| 4 | **Deterministic where possible** | `temperature=0.1`, explicit severity rubric, sequential id renumbering after sorting. |
| 5 | **Testable without the network** | The LLM is behind an `LLMClient` protocol; the entire suite runs on a fake. |
| 6 | **CI is the primary consumer** | Exit codes and severity gating are first-class, not an afterthought. |

---

## 3. System Architecture

### 3.1 Module Boundaries

```
scanner/
├── cli.py           Argument parsing, wiring, exit codes.        No business logic.
├── file_handler.py  Filesystem → SourceFile → CodeChunk.         No LLM knowledge.
├── core.py          Prompting, LLM transport, orchestration.     No I/O formatting.
├── models.py        Schemas, validation, severity semantics.     No dependencies on siblings.
└── reporter.py      ScanReport → terminal / JSON / Markdown.     Read-only over models.
```

The dependency graph is strictly acyclic and points inward toward `models.py`:

```
cli ──▶ core ──▶ file_handler ──▶ models
 │        │                          ▲
 └────────┴──────▶ reporter ─────────┘
```

This means `models.py` can be imported by anything (including downstream consumers of the JSON schema) without pulling in `google-genai`, `click`, or `rich`.

### 3.2 Data Flow

```
Path
 │  discover_files()          walk tree, apply extension + ignore filters
 ▼
list[Path]
 │  read_source_file()        size guard, binary sniff, utf-8 → latin-1 fallback
 ▼
SourceFile
 │  chunk_file()              overlapping line windows for large files
 ▼
CodeChunk
 │  build_user_prompt()       gutter-numbered code + file metadata
 ▼
str (prompt)
 │  GeminiClient.generate()   rate limit → request → retry/backoff
 ▼
str (raw JSON)
 │  parse_llm_response()      fence stripping, brace extraction, Pydantic validate
 ▼
LLMResponse
 │  Scanner.scan_file()       attach path, filter by severity, dedupe, sort, renumber
 ▼
FileScanResult
 │  ScanReport.rebuild_summary()
 ▼
ScanReport ──▶ reporter ──▶ terminal | JSON | Markdown
```

---

## 4. Key Design Decisions

### 4.1 Why structured output *and* Pydantic?

Gemini's `response_schema` constrains generation, but it is not a hard guarantee — the model can still emit a fence, prose, or a bare array. `parse_llm_response()` therefore layers three defenses:

1. Strip ```` ```json ```` fences if present.
2. Fall back to brace-slicing (`text.find("{")` … `text.rfind("}")`) if `json.loads` fails.
3. Validate the result with Pydantic; a schema violation raises `ScannerError`, which is captured per-file rather than crashing the scan.

**Decision:** belt and braces. The cost is ~40 lines; the benefit is that a single malformed response never kills a 200-file scan.

### 4.2 Severity as an ordered enum

`Severity` is a `str, Enum` with an explicit `rank` property and comparison dunders. Two reasons:

- Threshold filtering (`finding.severity >= self.severity_threshold`) reads naturally and has one source of truth.
- It stays a plain string in JSON, so downstream consumers need no special handling.

**Rejected alternative:** `IntEnum`. It serializes as an integer, which makes JSON reports less legible for humans.

### 4.3 Line-numbered prompts

The model is given the code with an explicit left gutter:

```
   17 |     cursor = conn.cursor()
   18 |     query = "SELECT * FROM users WHERE u = '" + username + "'"
```

and the system prompt states that these numbers are authoritative. Without this, models reliably drift by a few lines or restart counting at 1 inside a chunk, which makes findings unusable for IDE navigation and PR annotation.

### 4.4 Overlapping chunks

Files above `DEFAULT_CHUNK_LINES` (400) are split with a 20-line overlap. A vulnerability spanning lines 395–405 would be truncated in both windows without overlap; with it, at least one window contains the whole construct.

The cost is duplicate findings on the overlap region, handled by `_dedupe()` keyed on `(cwe_id, line_number_range, title.lower())`.

**Rejected alternative:** AST-aware chunking on function boundaries. Better fidelity, but it needs a parser per language and breaks on Terraform/YAML. Deferred.

### 4.5 Rate limiting is client-side

`RateLimiter` paces requests with a monotonic-clock sleep to stay under the free-tier RPM cap, and `GeminiClient` retries `429`/`5xx`/network errors with exponential backoff plus jitter (`delay + uniform(0, delay*0.25)`).

Retryability is decided by substring matching on the stringified exception (`_is_retryable`). This is deliberately loose: `google-genai` raises varied exception types across versions, and a false-positive retry is far cheaper than an aborted scan.

### 4.6 The `LLMClient` protocol

`core.Scanner` depends on a `Protocol` with a single `generate(system_prompt, user_prompt) -> str` method, not on `GeminiClient`. This makes the test suite hermetic (no key, no network, no mocking of the SDK's internals) and leaves the door open for other providers without touching orchestration logic.

### 4.7 Error taxonomy and exit codes

| Condition | Handling | Exit |
| --- | --- | --- |
| No findings at/above threshold | Normal report | `0` |
| Findings at/above threshold | Normal report | `1` |
| Missing `GEMINI_API_KEY` | `MissingAPIKeyError`, message to stderr | `2` |
| Target does not exist | Click validation / `FileNotFoundError` | `2` |
| Bad `--output` extension | Validated before any API call | `2` |
| Unreadable/binary/oversized file | Recorded in `FileScanResult.error`, scan continues | unaffected |
| Malformed LLM response for one chunk | Recorded per-file, other chunks continue | unaffected |

The `--output` extension is checked **before** the client is constructed, so a typo in the filename does not waste an entire scan's worth of API quota.

### 4.8 Model selection and pinning

`DEFAULT_MODEL` lives in `models.py`, the innermost module, and `core.py` re-exports it. Putting it anywhere else would either duplicate the literal or invert the dependency direction.

The default is a **pinned** id (`gemini-3.7-flash`) rather than a rolling alias like `gemini-flash-latest`. A scanner whose model can change underneath it produces reports that cannot be compared across runs, which breaks baselining and makes "did this regress?" unanswerable. The cost of pinning is that ids get retired — `gemini-2.0-flash` was retired mid-build and returned `404 NOT_FOUND` on the first live call — so the failure mode is a loud, immediate error rather than silent drift. That is the right trade for a security tool.

Resolution order, deliberately resolved in `cli.main()` *after* `load_dotenv()`:

```
--model flag  →  $LLM_APPSEC_MODEL  →  DEFAULT_MODEL
```

The flag wins for one-off overrides; the env var lets a team pin a different model per environment without touching code; the constant is the floor.

**Why not resolve the env var in the Click decorator?** Decorator defaults are evaluated at import time, before `load_dotenv()` runs, so a `.env`-supplied value would be silently ignored. The option defaults to `None` and is resolved in the function body instead.

### 4.9 The system prompt

Five design choices in `SYSTEM_PROMPT` are load-bearing:

1. **Explicit vulnerability taxonomy** — enumerating OWASP categories, secrets, IaC misconfigurations and crypto failures raises recall on categories the model would otherwise under-weight.
2. **"Report ONLY what you can point to"** — the single most effective anti-hallucination instruction; it forbids speculation about unseen code.
3. **"Do not report style or performance issues"** — without this, models pad results with linting noise and the report loses credibility.
4. **A concrete severity rubric** — mapping CRITICAL/HIGH/MEDIUM/LOW to exploitability makes severity comparable across files and runs.
5. **"An empty result is a correct and expected answer"** — models are strongly biased toward producing *something*. Explicitly blessing the empty array is what makes clean files actually come back clean.

---

## 5. Data Model

```python
ScanReport
├── tool, version, model, target, generated_at
├── severity_threshold: Severity
├── summary: ScanSummary
│   ├── files_discovered / files_scanned / files_failed
│   ├── total_findings
│   └── findings_by_severity: dict[str, int]
└── results: list[FileScanResult]
    ├── file_path, language, scanned, error
    └── vulnerabilities: list[Vulnerability]
        ├── vulnerability_id, title
        ├── cwe_id, owasp_category, severity
        ├── file_path, line_number_range
        ├── description, remediation
        └── code_patch: CodePatch
            ├── vulnerable_code
            ├── fixed_code
            └── explanation
```

**Normalizing validators** absorb the variation real models produce:

- `line_number_range` accepts `"42"`, `42`, `[42, 57]`, `(42, 57)` → all become a string.
- `cwe_id` accepts `"89"` → becomes `"CWE-89"`.

Every model sets `extra="ignore"` so an extra key from a future model version is dropped rather than raising.

---

## 6. Testing Strategy

| Layer | What is verified | Approach |
| --- | --- | --- |
| `file_handler` | Extension filtering, ignore-dirs, lockfiles, binary/empty/oversized rejection, chunk overlap, gutter numbering | Real temp filesystems |
| `models` | Severity ordering, line-range coercion, CWE normalization, summary math | Direct validation |
| Response parsing | Plain / fenced / prose-wrapped / bare-array JSON, non-JSON, invalid enum | Fixture strings |
| Prompting | Path, language and numbered code present; segment marker only when chunked | String assertions |
| `Scanner` | Path attachment, threshold filtering, sorting, renumbering, dedupe, per-file error isolation | `FakeClient` |
| Transport | Retry-then-succeed, give-up on non-retryable, rate-limiter sleep | Injected fake SDK + fake sleep |
| `reporter` | JSON round-trip, Markdown sections, clean-scan text, format rejection | Golden-ish assertions |
| `cli` | Exit `0`/`1`/`2` paths, `--no-fail`, threshold, output writing | `click.testing.CliRunner` |

**Rule: the suite never touches the network and never needs a key.** Any test that would require one is testing the SDK, not this tool.

---

## 7. Known Limitations

| Limitation | Impact | Mitigation / plan |
| --- | --- | --- |
| Per-file context only | Misses cross-file taint | Repo-level context pass (roadmap) |
| Non-deterministic output | Two runs may differ slightly | `temperature=0.1`; baseline file planned |
| Serial scanning | Slow on large repos | Concurrency with a shared limiter (roadmap) |
| Code leaves the machine | Data-governance concern | Documented prominently; local-model backend is a future option |
| Line-based chunking | Can split a function | AST-aware chunking (deferred) |
| No suppression mechanism | Accepted risks re-reported every run | Baseline/ignore file (roadmap) |

---

## 8. Future Work

1. **SARIF output** → native GitHub Code Scanning annotations.
2. **Baseline file** → `--baseline .appsec-baseline.json` to suppress known/accepted findings.
3. **Concurrency** → `asyncio` or a thread pool sharing one `RateLimiter`.
4. **Repository context pass** → a cheap first pass building a symbol/route map, injected into per-file prompts to enable cross-file reasoning.
5. **Auto-fix mode** → apply `code_patch` as a git diff behind `--fix --dry-run`.
6. **Pluggable backends** → the `LLMClient` protocol already allows a local/self-hosted model for teams that cannot send code externally.
