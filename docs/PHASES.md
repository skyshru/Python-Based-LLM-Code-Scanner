# Delivery Phases — llm-appsec-scanner

A running log of what shipped in each phase. Each entry records scope, what was delivered, verification, and decisions worth remembering.

---

## Phase 1 — Core Scanner ✅ Complete

**Dates:** 2026-08-15
**Status:** Complete · 53/53 tests passing

### Summary

Built the complete v0.1 scanner end to end: a working CLI that walks a codebase, sends each file to Gemini under a security-engineer system prompt, validates the structured response with Pydantic, and emits terminal, JSON and Markdown reports with CI-ready exit codes.

### Delivered

| Component | File | What it does |
| --- | --- | --- |
| Data model | `scanner/models.py` | `Severity` ordered enum, `Vulnerability`, `CodePatch`, `FileScanResult`, `ScanReport` with normalizing validators |
| File handling | `scanner/file_handler.py` | Extension allowlist (7 languages), directory/lockfile denylists, binary + size + encoding guards, overlapping chunking, gutter numbering |
| LLM core | `scanner/core.py` | System prompt, JSON response schema, `GeminiClient` with RPM limiting and jittered backoff, defensive response parsing, `Scanner` orchestration |
| Reporting | `scanner/reporter.py` | `rich` terminal output, JSON serialization, Markdown report, suffix-based writer |
| CLI | `scanner/cli.py` | All required flags plus `--rpm`, `--max-retries`, `--chunk-lines`, `--quiet`, `--no-fail`; exit codes 0/1/2 |
| Tests | `tests/test_scanner.py` | 53 tests over filtering, chunking, models, parsing, prompting, orchestration, transport, reporting, CLI |
| Samples | `tests/vulnerable_samples/` | SQLi/command-injection Python, hardcoded-secrets Python, insecure Terraform |
| Packaging | `pyproject.toml`, `requirements.txt`, `.env.example`, `.gitignore` | Installable package with `llm-appsec-scanner` console script |
| Docs | `README.md`, `docs/DESIGN.md`, `docs/FLOW.md`, `docs/PHASES.md` | GitHub-facing readme, architecture rationale, developer manual, this log |

### Requirements coverage

| Requirement | Status |
| --- | --- |
| CLI with `--target`, `--output`, `--severity-threshold`, `--model` | ✅ plus 5 extra flags |
| Python 3.10+, `google-genai`, `gemini-3.7-flash` | ✅ |
| Pydantic v2 structured output | ✅ two-layer: provider schema + client validation |
| All 9 required vulnerability fields | ✅ plus `confidence` |
| Ignore non-code dirs/files | ✅ 20 dirs, 9 lockfiles, binary/size guards |
| Supported extensions `.py .js .ts .go .java .tf .yaml` | ✅ plus `.jsx .tsx .tfvars .yml` |
| JSON + Markdown + colour terminal output | ✅ |
| Rate limiting and error handling | ✅ RPM pacing, jittered exponential backoff, per-file error isolation |
| Exit `0` clean / `1` findings | ✅ plus `2` for tool errors |
| pytest with mocked responses | ✅ 53 tests, zero network calls |

### Verification

```
$ pytest -q
53 passed in 4.89s

$ python -m scanner.cli --help
Usage: python -m scanner.cli [OPTIONS]
  LLM-assisted SAST scanner for OWASP/CWE-aligned vulnerability detection.
```

### Decisions worth remembering

1. **Two-layer output enforcement.** Gemini's `response_schema` constrains generation, but the client still strips fences, brace-slices, and Pydantic-validates. A malformed response fails one chunk, never the scan.
2. **`LLMClient` as a Protocol.** Orchestration depends on an interface, not on `GeminiClient`. This is what makes the suite hermetic and future providers cheap.
3. **Overlapping chunks + dedupe.** 20-line overlap keeps boundary-straddling flaws intact; `_dedupe()` on `(cwe, lines, title)` removes the resulting duplicates.
4. **Renumber after dedupe.** Ids are assigned last so `SEC-00N` sequences have no gaps.
5. **Exit `2` distinct from `1`.** CI can tell "found problems" from "scanner broke".
6. **`--output` validated before client construction.** A typo'd filename cannot waste a scan's worth of quota.
7. **"An empty result is correct."** Explicitly blessing the empty array in the prompt is what makes clean files actually come back clean.

### Known gaps carried forward

- Per-file context only — no cross-file taint analysis.
- Serial scanning; large repos are slow.
- No baseline/suppression file, so accepted risks re-report every run.
- No SARIF output.
- ~~End-to-end run against the live Gemini API not yet performed~~ → closed in Phase 2a.

---

## Phase 2 — Validation & Hardening ✅ Complete

**Dates:** 2026-08-15 → 2026-08-17
**Status:** Complete · 97/97 tests passing

Shipped: live end-to-end validation, a forced model migration, real-world false-positive triage and the prompt tuning that came out of it, fail-fast daily-quota handling, SARIF output, and `--baseline` suppression. The prompt tuning was then measured on the default model (2j, 2k): **zero false positives on the files that previously produced ~19, with true-positive recall confirmed intact.**

### 2a. First live run ✅

The Phase 1 gap — everything verified only against `FakeClient` — is now closed. The scanner was run against the real Gemini API on `tests/vulnerable_samples/`.

**Result:** 3 files scanned, 0 failed, **16 findings** (2 CRITICAL, 11 HIGH, 3 MEDIUM), exit code `1`.

| File | Findings | Representative detections |
| --- | --- | --- |
| `sample_hardcoded_keys.py` | 6 | `pickle.loads` RCE (CRITICAL), hardcoded AWS/Stripe/DB credentials, unsalted MD5 password hashing |
| `sample_insecure_s3.tf` | 5 | Public S3 bucket, `0.0.0.0/0` ingress on 22/5432, unencrypted publicly-accessible RDS |
| `sample_sqli.py` | 5 | SQLi via concatenation and f-string, command injection, path traversal |

**Line-number accuracy was spot-checked and correct** — `pickle.loads` reported at 35-37, secrets at 13-17, MD5 at 20-22, all matching the source exactly. The gutter-numbering design from Phase 1 works as intended. Patches were syntactically valid and semantically correct.

### 2b. Model migration ✅

`gemini-2.0-flash` — the model named in the original brief — **has been retired by Google** and now returns `404 NOT_FOUND`. Discovered on the first live call.

- Queried the live model list; selected **`gemini-3.7-flash`** as the new default (newest stable Flash tier: best reasoning-per-cost for one-call-per-file scanning, pinned for reproducibility).
- Moved `DEFAULT_MODEL` into `models.py` as the single source of truth; `core.py` re-exports it, preserving the `core → models` dependency direction.
- Updated all references across code, tests, and docs.

### 2c. Bug fixes ✅

| Issue | Fix |
| --- | --- |
| `LLM_APPSEC_MODEL` was advertised in `.env.example` but **never read** — dead config | Wired into `cli.main()`, resolved *after* `load_dotenv()` so `.env` can supply it. Precedence: `--model` → `$LLM_APPSEC_MODEL` → `DEFAULT_MODEL`. Covered by 3 new parametrized tests |
| SDK emitted an automatic-function-calling warning on every request, polluting scan output | Narrowly silenced the `google_genai.models` logger; we never pass tools, so the advice does not apply |

### 2d. Operational lesson worth recording

A `.env` containing the unedited placeholder `your-api-key-here` is **worse than no `.env` at all**: the string is truthy, so it passes the `MissingAPIKeyError` guard, the scan starts, and then dies on the first API call with an opaque auth error. The clean "key is not set" message never fires. Documented in the FLOW troubleshooting table.

### 2e. Stakeholder pitch deck ✅

A client-facing companion to `docs/DESIGN.md` (which stays as the technical reference). `docs/index.html` is a self-contained, single-file HTML page — no external requests, no build step — built around the real Phase 2a scan output: the actual `pickle.loads` finding as the hero diff, the actual 3-file/16-finding/severity-split numbers, and an honest complement-not-replace framing against Semgrep/Bandit/tfsec. Meant to be hosted directly via GitHub Pages (`main` / `/docs`) so it doesn't depend on any Claude-hosted link.

### 2f. False-positive measurement ✅ (partial — see open item below)

Tested against three real external codebases, not the vulnerable fixtures:

| Target | Language | Result |
| --- | --- | --- |
| `neet` (client-side quiz app) | JS | 0 findings on a 398-line file with 13 `innerHTML` sites and 2 `localStorage` uses — verified by hand that every site is genuinely safe (static literals or content cleared, never interpolated). A real negative, not a lucky one: `innerHTML` is exactly the keyword a naive pattern-matcher flags on sight. |
| ThePhish (open-source phishing-analysis tool) | Python/JS/YAML | See below. |
| `teslamotors/vehicle-command` | Go | Not run — 78 files / ~39,600 lines is too large for the free-tier daily quota (20 req/day); needs a paid tier or a deliberately scoped subset. |

**ThePhish, `gemini-3.7-flash` (the default model), partial run** (2 of 11 files before hitting the daily quota): `case_from_email.py` and `list_emails.py` — **0 findings on both**, despite both files reading IMAP/API credentials out of a config dict (`config['imapPassword']`, etc.) in exactly the pattern that later proved to be the dominant false-positive source on a smaller model. This is the strongest single data point that `gemini-3.7-flash` has meaningfully better precision than the lite tier.

**ThePhish, `gemini-2.5-flash-lite` (quota-forced substitute), full run**: 19 findings across 10 files. Manually triaged every finding against the actual source:

- **14 of 19 (~74%) were false positives or miscategorized.** The dominant pattern (8 findings, 42% of the total): every file that reads a secret via `config['x']` was flagged `CWE-798` Hardcoded Credentials — even though the code correctly reads from an external file, and `app/configuration.json` (confirmed by hand) is a template with every secret field set to `""`. The model speculated about a file it never saw, directly violating the system prompt's own "never speculate about code you cannot see" rule. Other false positives: a `UnicodeDecodeError` handling concern mislabeled `CWE-798`; TLP/PAP classification labels (not secrets) mislabeled `CWE-798`; a jQuery compatibility note mislabeled `CWE-20`; `document.createTextNode()` — a safe DOM API — flagged as "potential XSS" while the finding's own text admits it's safe; and one finding whose suggested "fix" **removed** an existing `flask.escape()` call, actively regressing security.
- **5 of 19 were plausible-to-real true positives**, most notably `MYSQL_PASSWORD=example` and `MYSQL_ROOT_PASSWORD=password` — literal weak passwords sitting in the committed `docker-compose.yml`. Also flagged: Elasticsearch security disabled, a Docker-socket mount into Cortex (arguably by-design for its sandboxed-analysis architecture), and unsanitized log data reaching `innerHTML`.

**Prompt tuning** ([`scanner/core.py`](../scanner/core.py)): rewrote `SYSTEM_PROMPT` rule 1 to explicitly state that reading a secret from `config['x']`/`os.environ[...]` is the *correct* pattern, not a finding, and that CWE-798 requires the literal secret value to be visible in the given code. Added a new rule requiring `cwe_id`/`owasp_category` to accurately describe the actual flaw (targeting the mismatched-CWE failures), and tightened the code-patch rule to forbid a "fix" that removes an existing security control (targeting the `flask.escape()` regression).

**Honest result of the re-test**: re-running the identical ThePhish scan with the tuned prompt on `gemini-2.5-flash-lite` made the targeted pattern *worse*, not better — `case_from_email.py` went from 4 to 12 findings, now flagging nearly every individual `config['x']` field (host, port, folder, TLP, PAP, tags) as a separate `CWE-798` finding. It also surfaced two additional, more sophisticated, plausible findings (email attachment filename → path traversal; email subject → stored XSS in a case title) not present in the first run. Read: a lite-tier model likely can't reliably parse a conditional rule ("only flag X if Y") and instead over-indexes on the topic being discussed at all — a model-capability ceiling, not obviously a prompt-wording problem.

**Open item**: the tuned prompt has *not yet* been validated against `gemini-3.7-flash` — the actual default/production model — because its free-tier daily quota (20 req/day) was already exhausted by the time the fix was ready to test. `gemini-3.7-flash` is the model that matters for this question, since it already showed clean judgment on this exact file under the *old* prompt. Re-test once quota resets. → **Resolved in 2j.**

### 2g. Fail fast on daily quota exhaustion ✅

The gap 2f surfaced in itself, fixed: once Google's free-tier *daily* request quota is exhausted, it was previously indistinguishable at the code level from a transient rate limit, so the scanner retried with backoff and then failed on **every remaining file individually** — a wall of near-duplicate 429 dumps burying the actual report, and real wall-clock time wasted retrying something that can't succeed until the quota resets.

- `_is_daily_quota_exhausted()` detects the `PerDay` marker in Google's `quotaId` and raises the new `DailyQuotaExceededError` immediately in `GeminiClient.generate()`, bypassing the retry loop entirely.
- `Scanner.scan_file()` lets it propagate instead of folding it into the per-chunk error list; `Scanner.scan()` catches it once, marks every remaining discovered file as skipped with a single shared reason, and stops.
- `ScanReport.truncated` / `truncation_reason` surface this in all three output formats (a warning line in the terminal, a blockquote near the top of the Markdown report, and the fields themselves in JSON).
- **Exit code is forced to `2` whenever a scan is truncated, unconditionally** — even if the files that did complete had CRITICAL findings. An incomplete scan must never be indistinguishable from a normal pass/fail result; CI should treat "the tool didn't finish" as its own failure mode, not quietly fold it into "found problems."
- Covered by 8 new tests (marker detection, no-retry-on-daily-quota, propagation through `scan_file`, stop-early + skip-marking in `scan`, the forced exit code, and the Markdown warning). 64/64 tests passing.

### 2h. SARIF output ✅

A fourth `reporter.py` format — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) — so findings can land as native inline PR annotations in GitHub's Security tab instead of a separate file someone has to remember to open. No API calls needed to build or test this; it's a pure transformation of an existing `ScanReport`, chosen over `--baseline` specifically for that reason (see the recommendation at the top of this phase).

- `render_sarif()` in `scanner/reporter.py`: deduplicates rules by `cwe_id` (one rule definition per CWE, one result per finding instance — matches how SARIF-consuming tools expect grouping to work); maps `Severity` to both SARIF's three-level `level` field and GitHub's separate `security-severity` 0–10 score, since they serve different UI purposes and only one of them has room for four buckets.
- `_parse_line_region()` degrades gracefully: extracts min/max digits from the free-form `line_number_range` string and omits the `region` entirely if none are found, rather than fabricating a line number.
- `partialFingerprints` gives GitHub a stable-ish identity per finding (`sha256(file_path | cwe_id | title)`) so repeat runs are tracked as the same alert rather than new ones — explicitly framed as a hint, not a solution to the harder cross-run matching problem `--baseline` will need to solve, especially given 2f's finding that the same underlying issue can come back reworded or under a different CWE on a non-deterministic model.
- `report.truncated` (from 2g) carries through to SARIF too: a quota-truncated scan sets `invocations[0].executionSuccessful = false` with an explanatory notification, so GitHub's own UI can't present an incomplete run as a clean one.
- `write_report()` and the CLI's `--output` validation both accept `.sarif` and `.sarif.json`; a GitHub Actions example using `github/codeql-action/upload-sarif` was added to the README.
- Full design rationale in [DESIGN.md §4.10](DESIGN.md#410-sarif-output). Covered by 11 new tests (region parsing across malformed inputs, rule deduplication, severity mapping, truncation reflection, both output extensions, and CLI end-to-end). 75/75 tests passing.

**Re-checked the `gemini-3.7-flash` quota before starting this item** (a single-file probe) — still exhausted, and the daily-quota fail-fast fix from 2g confirmed itself working correctly in the process: one clean attempt, one clear message, immediate exit `2`, instead of yesterday's wall of repeated retries. Prompt validation against the default model remains open.

### 2i. `--baseline` suppression file ✅

New module `scanner/baseline.py`. Designed deliberately, not reused from SARIF's fingerprint — the two problems look similar but aren't the same problem, and 2f's own data ruled out the obvious naive approach before any code was written.

- **Match rule, grounded in observed behavior, not theory:** exact match on `file_path` and `cwe_id`, fuzzy match on line range (overlap or within `LINE_TOLERANCE = 3` lines). Title is never matched on. This is a direct response to 2f: the same underlying issue came back reworded and with a different finding count between two runs of the same model on the same file, while `cwe_id` stayed exactly stable — so matching on wording, the way the SARIF fingerprint does, would have meant the baseline silently stopping working the moment the model rephrased something.
- **Workflow:** `--baseline PATH --update-baseline` accepts everything currently found (creating the file if needed); `--baseline PATH` alone suppresses matches on later runs. Both use the same underlying `update_baseline()`/`apply_baseline()` matching logic, so `--update-baseline` is additive and idempotent by construction — re-running it against unchanged code never grows the file, because it checks each finding against existing entries with the same tolerance before appending, not a separate dedup pass.
- **Suppressed, not deleted:** `Vulnerability.suppressed` marks a finding in place rather than removing it from the report. `ScanReport.active_findings` (new) — everything except suppressed — is what now drives `summary.total_findings`, the severity table, and the exit code; `ScanReport.findings` (existing) still returns everything, so JSON stays a complete audit trail. Zero behavior change when `--baseline` isn't used.
- Markdown and terminal output list suppressed findings in a separate, compact section (file, line, title, CWE — no patch detail) rather than hiding them; SARIF marks them with a native `suppressions` entry so GitHub Code Scanning shows them as dismissed rather than open.
- Full design rationale, including the explicit tradeoff being made (false negatives on genuinely new-but-nearby findings, traded for not re-flagging accepted findings on every run) in [DESIGN.md §4.11](DESIGN.md#411-baseline-suppression). Covered by 22 new tests (matching rules, idempotency, reworded-title resilience, both CLI flags end-to-end). 97/97 tests passing.

### 2j. Prompt validation on the default model ✅ (partial — scope-limited by quota)

**Date:** 2026-08-16. Closes the open item from 2f.

Once `gemini-3.7-flash`'s daily quota reset, the tuned prompt was run against `app/case_from_email.py` — the single most diagnostic file available, since it is where `gemini-2.5-flash-lite` produced **12 findings under this exact same tuned prompt**, nearly all of them `config['x']` reads mislabeled `CWE-798`.

**Result: 0 findings.** Same prompt, same file, opposite outcome from the lite model.

This confirms the hypothesis recorded in 2f rather than merely being consistent with it: the tuned rule ("reading a secret from a config object is the *correct* pattern; only flag CWE-798 when the literal value is visible") is parsed and applied correctly by `gemini-3.7-flash`, while a lite-tier model over-indexes on the topic being mentioned at all. **The prompt change did not degrade the good model** — which was the actual risk worth checking, given the change was authored in response to a smaller model's failures.

**Scope limits at time of writing:** this was one file; recall and a broader false-positive picture remained unmeasured. → **Both closed the following day, below.**

### 2k. Precision and recall measured on the default model ✅

**Date:** 2026-08-17. Closes the two scope gaps left open in 2j, using a fresh daily quota deliberately (quota is perishable; Phase 3 work needs none of it, so spending it on measurement first was the correct ordering).

**The recall question first**, since it was the higher risk: could the anti-speculation tuning have *suppressed* genuine findings? Scanned `docker/docker-compose.yml` — the file holding the run's real true positives.

**Result: 3 HIGH findings, all genuine, and better classified than before.**

| Issue | lite model (tuned) | `gemini-3.7-flash` (tuned) |
| --- | --- | --- |
| `MYSQL_PASSWORD=example` / `MYSQL_ROOT_PASSWORD=password` | 2 separate findings | 1 consolidated finding, `CWE-798` — correct, since the literal secret **is** visible in the given code, exactly the condition the tuned rule permits |
| Unauthenticated Elasticsearch on all interfaces | `CWE-269` (wrong) | `CWE-306` Missing Authentication — accurate |
| Docker socket mounted into container | `CWE-269` (wrong) | `CWE-250` Execution with Unnecessary Privileges — accurate |
| **Total** | 5 findings | 3, correctly labeled |

Verified by hand that the `CWE-798` finding's `vulnerable_code` matches source lines 81-85 verbatim. Recall is intact, and prompt rule 3 (accurate CWE/OWASP labeling) is demonstrably working on this model — the two mislabeled `CWE-269` findings from the lite run came back correctly classified.

**The precision question second.** A full-repo scan reached 5 of 11 files before the daily cap (chunked files consume several requests each, so "20/day" covers far fewer than 20 files). The files it did complete are the ones that matter most — **exactly the four Python files that produced the bulk of the lite model's false positives**:

| File | lite model (tuned prompt) | `gemini-3.7-flash` (tuned prompt) |
| --- | --- | --- |
| `app/case_from_email.py` | 12 findings, nearly all `config['x']` → `CWE-798` FPs | **0** |
| `app/run_analysis.py` | 6 findings, same pattern | **0** |
| `app/list_emails.py` | 1 FP | **0** |
| `app/thephish_app.py` | 1 FP — the one whose "fix" removed `flask.escape()` | **0** |
| `app/ws_logger.py` | 0 | **0** (measured 2026-08-16) |

**Zero false positives across the four files that generated roughly nineteen of them on the lite model, with true-positive recall confirmed intact on the fifth.** That is the measurement 2f asked for, on the model that actually ships.

**Remaining unmeasured:** the four JavaScript files (`bootstrap.min.js`, `bs-init.js`, `theme.js`, `thephish.js`). On the lite model these produced 3 findings, 2 of them false positives (a jQuery compatibility note mislabeled `CWE-20`; `document.createTextNode()` — a safe API — flagged as "potential XSS"). Worth checking eventually, but they are lower-signal than the Python files already covered, and no conclusion here depends on them.

**Standing conclusion, unchanged:** the free tier's 20 req/day cap is the binding constraint on further validation, not any property of the tool. The `teslamotors/vehicle-command` scan (78 files, ~39,600 lines) needs a paid tier to be feasible at all.

### Remaining in Phase 2

Nothing blocking. The prompt-validation item is resolved as far as the free tier allows (2j); the residual scope gaps there are measurement limits, not open work, and are better closed by a paid tier than by more free-tier attempts.

---

## Phase 3 — Scale & Performance 🟡 In Progress

**Dates:** started 2026-08-17
**Status:** 119/119 tests passing

### 3a. Response caching ✅

New module `scanner/cache.py`. Chosen as the first Phase 3 item because it needs no API quota to build or test, and because it directly attacks the constraint that had been limiting every previous phase: a free-tier key allows ~20 requests/day, and a chunked file consumes several, so re-scanning a repo after editing two files would burn a day's budget re-analyzing unchanged code.

- **A decorator over the `LLMClient` protocol**, not a change to `GeminiClient`. `Scanner` required zero changes. It also places the cache *outside* the rate limiter (which lives inside `GeminiClient`), so a hit costs neither quota nor the RPM pacing sleep — embedding it inside the client would have made every hit wait out the rate-limit interval for nothing.
- **Key = `sha256(cache_format_version, model, system_prompt, user_prompt)`.** `user_prompt` already carries file path, language, chunk boundaries and the numbered source, so content and chunking changes are covered for free. Including `system_prompt` is not defensive padding — it is a direct response to this project's own history: the prompt was retuned in 2f, and a cache blind to that would have silently served pre-tuning results while 2j/2k believed they were measuring the new prompt.
- **On by default.** Defensible for a security tool specifically because the key is content-addressed: a hit can only occur when file, prompt and model are byte-identical to a previous run, so the cached answer is the answer a fresh query would give. Given model non-determinism this makes runs *more* reproducible, not less. `--no-cache` and a disposable cache directory cover the residual risk of a provider improving a model behind a stable id.
- **A broken cache may never break a scan.** Writes happen only after a successful response, so quota errors and malformed responses propagate uncached rather than being memoized as answers; corrupt entries degrade to misses; an unwritable directory is swallowed.

**Bug found and fixed during implementation, worth recording.** Wiring caching on by default immediately broke three existing CLI tests. Cause: `--cache-dir` defaults to a *relative* path, so the cache landed in the repo root during tests, and tests scanning identical trivial content (`x = 1`) produced identical cache keys — one test's findings leaked into another test's supposedly-clean scan, turning an expected exit `0` into exit `1`. Fixed with an autouse fixture that runs every test in an isolated working directory, which also stops the suite writing a cache directory into the repo. The failure was a genuine test-isolation gap that the feature merely exposed.

- Covered by 12 new tests: hit/miss behavior, persistence across client instances, key invalidation for each of model/system-prompt/user-prompt independently, corrupt-entry and unwritable-directory degradation, failures not being cached, end-to-end reuse through `Scanner`, edited files correctly missing, and both CLI flags.
- Full rationale in [DESIGN.md §4.12](DESIGN.md#412-response-caching); walkthrough in [FLOW.md Module 5b](FLOW.md#module-5b--response-caching).

### 3b. Concurrent file scanning ✅

`Scanner.scan()` now runs files through a `ThreadPoolExecutor`, default 4 workers, all sharing one `RateLimiter` so `--rpm` remains the hard cap. Threads rather than asyncio: the SDK call is blocking I/O, and threads keep `LLMClient` a plain synchronous protocol instead of forcing an async rewrite through client, scanner and CLI for no extra throughput.

**A latent thread-safety bug had to be fixed first, and it was silent.** The existing `RateLimiter` compared against `_last_call` and *then* slept, updating the timestamp afterwards. Single-threaded that is correct; with several workers they all read the same timestamp, all compute the same wait, and all fire simultaneously — breaking the RPM cap precisely when concurrency makes it matter. Replaced with slot reservation: reserve under a lock, wait outside it, so reservations serialize while waiting overlaps. The regression test asserts the eight recorded waits are *distinct*; replaying it against the old implementation yields **one** distinct value across all eight threads, which is exactly the failure signature — verified before trusting the test.

**Two more shared-state hazards, both introduced by yesterday's cache and fixed here:** `CacheStats` counters (`+= 1` is not atomic, so concurrent workers would silently undercount — now locked) and cache writes (two workers racing on one key — now write-to-temp plus `os.replace`, so a reader never observes a half-written entry, and either winner is correct since the contents are identical).

**Measured speedup, stated with its caveat rather than as a headline number.** Simulated over 12 files with representative latency and a real `RateLimiter`:

| Workers | Rate-limit-bound (low `--rpm`) | Latency-bound (high `--rpm`) |
| --- | --- | --- |
| 2 | 1.8x | 2.0x |
| 4 | 1.9x **(plateau)** | 3.7x |
| 8 | 1.9x (no further gain) | 5.4x |

At low RPM the wall time matches the limiter's theoretical floor almost exactly, so extra workers do nothing — **on a free-tier key this is roughly a 1.9x win, not a 5x one.** Concurrency scales properly only once `--rpm` stops binding, i.e. on a paid tier. Default 4 sits at the plateau for slow tiers with headroom for fast ones.

**Determinism and quota fail-fast both preserved.** Workers write into a pre-sized list at their own index and the report is assembled in discovery order, so a concurrent scan yields a byte-identical report to a serial one (verified by a test running both). Quota fail-fast needed its semantics restated: concurrently there is no clean "stopped at file N" boundary, since file 8 can finish after file 7 hits the quota. An unfilled slot now means *never attempted*, a `threading.Event` stops workers that have not started, and the truncation message reports counts rather than a position. Files that already completed keep their results — discarding them would waste quota already spent.

- 9 new tests: observable overlap, strict serialism at `--concurrency 1`, concurrent-vs-serial report equality, quota stop under concurrency, workers not firing after a quota stop, rate-limiter thread safety, zero-RPM bypass, and both CLI flags. Two existing test helpers were made thread-safe, since their unguarded `+= 1` would otherwise have made the new tests flaky.
- Rationale in [DESIGN.md 4.13](DESIGN.md#413-concurrent-scanning); walkthrough in [FLOW.md Module 4a](FLOW.md#module-4a--concurrency).

### Remaining in Phase 3

- Git-diff mode (`--changed-only`) for fast PR scans. Composes well with 3a: caching already makes unchanged files cheap, and this would avoid even discovering them.
- Repository context pass to enable cross-file reasoning — the hardest item, and the one that addresses the per-file-context limitation carried since Phase 1.

---

## Phase 4 — Distribution 🔜 Planned

- Publish to PyPI.
- Ship a GitHub Action wrapper.
- Publish a container image.
- Pluggable local/self-hosted model backend for teams that cannot send code externally.
