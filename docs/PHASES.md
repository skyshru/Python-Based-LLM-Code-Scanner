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

## Phase 2 — Validation & Hardening 🟡 In Progress

**Dates:** started 2026-08-15
**Status:** live validation complete · 56/56 tests passing

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

**Open item**: the tuned prompt has *not yet* been validated against `gemini-3.7-flash` — the actual default/production model — because its free-tier daily quota (20 req/day) was already exhausted by the time the fix was ready to test. `gemini-3.7-flash` is the model that matters for this question, since it already showed clean judgment on this exact file under the *old* prompt. Re-test once quota resets.

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

### Remaining in Phase 2

- Validate the tuned prompt against `gemini-3.7-flash` once quota resets (see 2f above) — the only item left, and it's blocked on Google's schedule rather than anything in our control.

---

## Phase 3 — Scale & Performance 🔜 Planned

- Concurrent file scanning sharing one `RateLimiter`.
- Response caching keyed on file content hash, to skip unchanged files.
- Git-diff mode (`--changed-only`) for fast PR scans.
- Repository context pass to enable cross-file reasoning.

---

## Phase 4 — Distribution 🔜 Planned

- Publish to PyPI.
- Ship a GitHub Action wrapper.
- Publish a container image.
- Pluggable local/self-hosted model backend for teams that cannot send code externally.
