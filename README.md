# llm-appsec-scanner

> LLM-assisted Static Application Security Testing (SAST) for source code repositories, powered by Google Gemini.

`llm-appsec-scanner` reads your source files, sends each one to a large language model under a security-engineer system prompt, and returns **structured, schema-validated vulnerability findings** aligned to OWASP Top 10 and CWE — each with a severity rating, a precise line range, remediation guidance, and a before/after code patch.

It exits with code `1` when it finds something actionable, so it drops straight into a CI/CD pipeline as a gate.

**[→ View the pitch deck](https://skyshru.github.io/Python-Based-LLM-Code-Scanner/)** — a shorter, visual walkthrough with real findings from a live scan, for anyone evaluating this before reading the code. (Source: [docs/index.html](docs/index.html); enable it once under repo *Settings → Pages → Deploy from a branch → `main` / `/docs`*.)

---

## Why an LLM scanner?

Traditional SAST tools match patterns. They are fast and deterministic, but they cannot reason about *intent*: they miss logic flaws, broken authorization, insecure design, and context-dependent misconfigurations, and they generate large volumes of false positives that teams learn to ignore.

An LLM reads code the way a security reviewer does. It understands that `user_id` coming from a request parameter and used directly in a database lookup is a broken-access-control problem, even when the query itself is parameterized.

This tool is designed to **complement** rule-based scanners (Semgrep, Bandit, tfsec), not replace them. Rule engines give you precision and speed on known patterns; this gives you reasoning and coverage on the rest.

---

## Features

| Capability | Detail |
| --- | --- |
| **Multi-language** | Python, JavaScript/TypeScript, Go, Java, Terraform, YAML (k8s/CI) |
| **OWASP + CWE aligned** | Every finding carries a CWE id and an OWASP Top 10 (2021) category |
| **Schema-enforced output** | Gemini structured output + Pydantic v2 validation — no prose, no drift |
| **Actionable patches** | Each finding includes verbatim vulnerable code and a working secure replacement |
| **Severity gating** | `--severity-threshold` filters findings and controls the exit code |
| **Smart file filtering** | Skips `.git`, `node_modules`, `__pycache__`, `.venv`, lockfiles, binaries, oversized blobs |
| **Chunking with overlap** | Large files are split into overlapping line windows so nothing straddles a boundary |
| **Rate limiting + retry** | Client-side RPM pacing and exponential backoff with jitter on `429`/`5xx` |
| **Three output modes** | Colour-coded terminal, machine-readable JSON, shareable Markdown |
| **CI-native exit codes** | `0` clean · `1` findings at/above threshold · `2` tool error |

---

## Installation

```bash
git clone https://github.com/<your-username>/llm-appsec-scanner.git
cd llm-appsec-scanner

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -e .
```

Set your API key ([get one free at Google AI Studio](https://aistudio.google.com/apikey)):

```bash
cp .env.example .env
# then edit .env and set GEMINI_API_KEY=...
```

Or export it directly:

```bash
export GEMINI_API_KEY="your-key"     # Windows PowerShell: $env:GEMINI_API_KEY="your-key"
```

> **Note:** leaving the placeholder `your-api-key-here` in `.env` is worse than having no `.env` — the string is truthy, so it passes the startup check and then fails on the first API call with an opaque auth error. Replace it with a real key, or delete the line.

Google retires model ids periodically. If you see `404 NOT_FOUND … model is no longer available`, pass a current one with `--model` or set `LLM_APPSEC_MODEL` in `.env`.

---

## Usage

Scan a directory and print results to the terminal:

```bash
llm-appsec-scanner --target ./src
```

Scan a single file, write a JSON report, and only fail on HIGH or above:

```bash
llm-appsec-scanner \
  --target ./src/api/auth.py \
  --output reports/auth.json \
  --severity-threshold HIGH
```

Produce a Markdown report for a PR comment:

```bash
llm-appsec-scanner -t ./terraform -o security-report.md
```

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--target`, `-t` | *(required)* | File or directory to scan |
| `--output`, `-o` | — | Report path; format inferred from `.json` / `.md` |
| `--severity-threshold` | `LOW` | Minimum severity to report and fail on |
| `--model` | `gemini-3.7-flash` | Gemini model id. Falls back to `$LLM_APPSEC_MODEL`, then the built-in default |
| `--rpm` | `15` | Client-side requests-per-minute cap |
| `--max-retries` | `4` | Retries on quota/transient errors |
| `--chunk-lines` | auto | Lines per request for large files |
| `--quiet`, `-q` | off | Summary table only |
| `--no-fail` | off | Always exit `0` (report-only mode) |

---

## Output

### Terminal

```
╭──────────────────────────────────────────╮
│ llm-appsec-scanner  •  model gemini-3.7-flash │
│ target ./src                              │
╰──────────────────────────────────────────╯

        Findings by Severity
┏━━━━━━━━━━━━┳━━━━━━━┓
┃ Severity   ┃ Count ┃
┡━━━━━━━━━━━━╇━━━━━━━┩
│  CRITICAL  │     1 │
│  HIGH      │     3 │
│  MEDIUM    │     2 │
│  LOW       │     0 │
└────────────┴───────┘

 HIGH  SEC-001  SQL Injection via Direct Parameter Concatenation
src/db.py:18-20  •  CWE-89  •  A03:2021-Injection
```

### JSON

```json
{
  "tool": "llm-appsec-scanner",
  "model": "gemini-3.7-flash",
  "summary": {
    "files_scanned": 12,
    "total_findings": 6,
    "findings_by_severity": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 0 }
  },
  "results": [
    {
      "file_path": "src/db.py",
      "vulnerabilities": [
        {
          "vulnerability_id": "SEC-001",
          "title": "SQL Injection via Direct Parameter Concatenation",
          "cwe_id": "CWE-89",
          "owasp_category": "A03:2021-Injection",
          "severity": "HIGH",
          "line_number_range": "18-20",
          "description": "...",
          "remediation": "...",
          "code_patch": { "vulnerable_code": "...", "fixed_code": "..." }
        }
      ]
    }
  ]
}
```

---

## Architecture

```text
                       ┌──────────────────┐
   llm-appsec-scanner  │     cli.py       │  argument parsing, exit codes
   --target ./src ────▶│   (click)        │
                       └────────┬─────────┘
                                │
                    ┌───────────▼────────────┐
                    │    file_handler.py     │  walk tree, filter, decode,
                    │  discover → read →     │  chunk into overlapping
                    │  chunk                 │  line windows
                    └───────────┬────────────┘
                                │  CodeChunk
                    ┌───────────▼────────────┐
                    │        core.py         │  system prompt + numbered code
                    │  Scanner ─ GeminiClient│  rate limit, retry/backoff
                    └───────────┬────────────┘
                                │  raw JSON
                    ┌───────────▼────────────┐
                    │      models.py         │  Pydantic v2 validation,
                    │  LLMResponse →         │  severity filter, dedupe,
                    │  Vulnerability         │  renumber
                    └───────────┬────────────┘
                                │  ScanReport
                    ┌───────────▼────────────┐
                    │     reporter.py        │
                    └──┬──────────┬──────────┘
                       │          │          │
                   terminal     JSON      Markdown
```

Full design rationale lives in [docs/DESIGN.md](docs/DESIGN.md). A module-by-module walkthrough of how it was built is in [docs/FLOW.md](docs/FLOW.md).

---

## CI/CD Integration

### GitHub Actions

```yaml
name: LLM Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  appsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install scanner
        run: pip install llm-appsec-scanner

      - name: Run scan
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: |
          llm-appsec-scanner \
            --target ./src \
            --output security-report.md \
            --severity-threshold HIGH

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.md
```

The job fails when a HIGH or CRITICAL finding is present. Add `--no-fail` while you are baselining an existing codebase.

### GitLab CI

```yaml
appsec_scan:
  image: python:3.11
  script:
    - pip install llm-appsec-scanner
    - llm-appsec-scanner -t ./src -o security-report.json --severity-threshold HIGH
  artifacts:
    when: always
    paths: [security-report.json]
  allow_failure: false
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: llm-appsec-scanner
        name: LLM AppSec Scan
        entry: llm-appsec-scanner --severity-threshold CRITICAL --target
        language: system
        types: [python]
```

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

The test suite runs entirely against a `FakeClient` — **no API key and no network calls are required**. `tests/vulnerable_samples/` holds deliberately insecure files (SQLi, hardcoded keys, insecure Terraform) used as scanner input.

```bash
pytest -q                      # full suite
pytest -q -k reporter          # one area
```

---

## Limitations & Responsible Use

- **This is not a substitute for a security review.** It is an assistive tool. A human must triage every finding.
- **LLMs can hallucinate.** The prompt constrains the model to code it can actually see, and the schema rejects malformed output, but false positives and false negatives both occur.
- **Per-file context.** Findings that require cross-file dataflow (taint from one module into another) are outside the current scope.
- **Your code is sent to Google's API.** Do not scan repositories you are not permitted to transmit to a third party. Check your organization's data-handling policy first.
- **Cost and quota.** One request per file (more for large files). Use `--severity-threshold` and narrow `--target` paths on large repos.

---

## Roadmap

- [ ] Cross-file taint analysis with a repository-level context pass
- [ ] SARIF output for GitHub Code Scanning
- [ ] Baseline/suppression file to ignore accepted risks
- [ ] Concurrent file scanning with a shared rate limiter
- [ ] Auto-fix mode that applies `code_patch` as a git diff

---

## License

MIT
