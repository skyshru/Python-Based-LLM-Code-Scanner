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

### Remaining in Phase 2

- Measure false-positive rate on a known-clean codebase.
- Tune the system prompt based on observed failure modes.
- Add a `--baseline` file to suppress accepted risks.
- Add SARIF output for GitHub Code Scanning.

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
