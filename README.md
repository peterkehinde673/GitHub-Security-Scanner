# GitHub Security Scanner

[![CI](https://github.com/peterkehinde673/GitHub-Security-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/peterkehinde673/GitHub-Security-Scanner/actions/workflows/ci.yml)
[![Live Scanner](https://img.shields.io/badge/Live%20Scanner-Open-blue?logo=render)](https://github-security-scanner.onrender.com/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Marketplace-blue?logo=githubactions)](https://github.com/marketplace/actions/github-security-scanner)

**Scan a public GitHub repository for security risks in seconds — without executing its code.**

GitHub Security Scanner is a modular static-analysis service that checks public repositories for exposed secrets, dangerous code patterns, dependency risks, and security configuration issues. It produces a deterministic **0–100 security score**, severity-ranked findings, evidence, and remediation guidance.

### Try it

**Web scanner:** https://github-security-scanner.onrender.com/

**GitHub Action:** https://github.com/marketplace/actions/github-security-scanner

---

## What it checks

| Area | What it looks for |
| --- | --- |
| 🔐 Secrets | AWS keys, GitHub tokens, OpenAI keys, Slack webhooks, private keys, JWTs, database connection strings, entropy-based secret candidates |
| ⚠️ Code patterns / SAST | SQL injection, OS command injection, React XSS, path traversal, Python `pickle` deserialization, disabled TLS verification |
| 📦 Dependencies | Supported manifest files, unpinned/wildcard versions, and curated known-advisory matches |
| 🛡️ Configuration | Docker root execution, production debug flags, permissive CORS, committed `.env` files |
| 📊 Scoring | Deterministic 0–100 score with severity deductions and letter grade |

The scanner is designed for **static analysis**. It does **not** execute code from the repository and does not install dependencies from the repository being scanned.

> **Important:** This is a lightweight security scanner, not a replacement for a full penetration test, expert code review, CodeQL, or an enterprise security platform.

---

## Quick start — web

1. Open the hosted scanner: https://github-security-scanner.onrender.com/
2. Enter a **public GitHub repository URL**.
3. Start the scan.
4. Review the score, findings, evidence, and remediation guidance.

No checkout or local setup is required for a web scan.

---

## Quick start — GitHub Actions

Install the companion Action from GitHub Marketplace:

https://github.com/marketplace/actions/github-security-scanner

Add this workflow to a repository:

```yaml
name: Security Scan

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Scan repository
        uses: peterkehinde673/github-security-scanner-action@v1
```

The Action scans the public repository that triggered the workflow by default. A checkout step is not required because the scanner retrieves repository data through GitHub's public repository APIs.

### Fail CI on serious findings

You can choose the minimum severity that fails the workflow:

```yaml
- name: Scan repository
  uses: peterkehinde673/github-security-scanner-action@v1
  with:
    fail-on: high
```

Supported values:

- `critical`
- `high` (default)
- `medium`
- `low`

The Action also exposes `score` and `findings` outputs for downstream workflow steps.

> The hosted Action currently supports **public repositories only**. Do not provide private-repository credentials or secrets to the scanner.

---

## Architecture

```text
Public GitHub repository
          │
          ▼
   Repository fetch layer
          │
          ├── bounded file selection
          ├── path validation
          ├── size limits
          └── timeout/concurrency controls
          │
          ▼
      Scan pipeline
          │
    ┌─────┼─────────┬────────────┐
    ▼     ▼         ▼            ▼
 Secrets SAST   Dependencies  Configuration
    │     │         │            │
    └─────┴─────────┴────────────┘
                  │
                  ▼
        Deterministic scoring
                  │
                  ▼
       Findings + remediation
```

The backend is organized into independent scanner modules so individual detection areas can evolve without turning the application into one large scanning routine.

---

## Security hardening

The scanner treats repository content as **untrusted input** and applies multiple defensive limits before analysis.

- Request JSON body limit: **12 MB**.
- Scan limit: **200 files** per request.
- Individual file limit: **500 KB** based on actual UTF-8 bytes.
- Total scan payload limit: **10 MB**.
- GitHub tree candidate limit: **10,000 items** with explicit truncation/coverage reporting.
- GitHub raw-file downloads use timeouts and streaming byte limits.
- Repository file downloads use bounded concurrency.
- File paths are validated against absolute paths, POSIX/Windows traversal, drive prefixes, control characters, and null bytes.
- Duplicate logical paths are deduplicated.
- Expensive API routes use in-memory rate limiting.
- Production CORS is environment-configured and fail-closed when no origin is configured.
- Errors are sanitized so internal stack traces, filesystem paths, and credentials are not returned to clients.
- Gemini-powered explanations treat repository content as untrusted data and apply prompt-boundary protections.

These controls reduce common abuse and resource-exhaustion risks, but no application can guarantee perfect protection against every malicious input.

---

## Detection engine

### Secret scanner

Uses pattern matching plus entropy checks to identify likely credentials while attempting to suppress obvious placeholders and sample values. Evidence is masked before it is shown in reports.

### Code-pattern scanner

Provides targeted, regex-based SAST-style detections for high-risk patterns. It is intentionally lightweight and should not be described as a complete AST-based vulnerability analysis engine.

### Dependency scanner

Parses supported dependency manifests and checks for unsafe version specifications and a curated set of known advisory patterns. It does not run the target repository's package manager and does not install target dependencies.

### Configuration scanner

Checks selected infrastructure and application configuration patterns such as Docker privilege issues, debug settings, permissive CORS, and committed environment files.

### Scoring

The baseline score starts at **100** and applies deterministic severity penalties:

- Critical: `-25`
- High: `-15`
- Medium: `-8`
- Low: `-3`

The score is bounded to `0–100` and accompanied by severity counts and a letter grade.

---

## API

The backend exposes the scanner service through API routes used by the web application and GitHub Action integration, including:

- `GET /api/health` — health check
- `POST /api/scan` — scan supplied repository file data
- GitHub repository metadata/file retrieval routes used by the Action and web scanner
- AppSec Copilot chat routes when Gemini is configured

The API applies validation, payload limits, rate limiting, and safe error handling at its boundaries.

---

## Local development

### Requirements

- Node.js 20+
- npm

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Run the authoritative test suite:

```bash
npm test
```

Type-check the project:

```bash
npm run lint
```

Build the production client and server bundle:

```bash
npm run build
```

Start the production bundle:

```bash
npm start
```

---

## Environment variables

See `.env.example`.

| Variable | Purpose |
| --- | --- |
| `GEMINI_API_KEY` | Optional Google GenAI key for AppSec Copilot explanations |
| `GITHUB_TOKEN` | Optional GitHub token for higher GitHub API rate limits |
| `CORS_ORIGIN` | Allowed browser origins in production |
| `RATE_LIMIT_WINDOW_MS` | Rate-limit window; defaults to 60 seconds |
| `RATE_LIMIT_MAX_REQUESTS` | General rate-limit ceiling |
| `PORT` | HTTP port; Render supplies this automatically |

Do not commit real credentials, tokens, or private keys. Use environment variables or your deployment platform's secret manager.

---

## Testing

The repository includes Node/TypeScript tests covering:

- secret detection and evidence masking
- SAST-style code-pattern detection
- dependency checks
- configuration checks
- deterministic scoring
- API payload and file-size limits
- path traversal defenses
- duplicate-path handling
- GitHub fetch controls
- rate limiting
- CORS behavior
- safe error handling
- target metadata and Git reference validation

Run the complete suite with:

```bash
npm test
```

The CI workflow also runs tests, type-checking, and the production build on pushes and pull requests.

---

## Project repositories

**Scanner engine + web application**

https://github.com/peterkehinde673/GitHub-Security-Scanner

**GitHub Actions integration**

https://github.com/peterkehinde673/github-security-scanner-action

**Hosted scanner**

https://github-security-scanner.onrender.com/

---

## Security disclosure

Please do not publish sensitive vulnerability details in a normal issue. See [`SECURITY.md`](SECURITY.md) for the preferred reporting process.

## Status and scope

This project is actively evolving. The scanner currently focuses on public repositories and deterministic static analysis. Detection coverage will expand over time, but findings should always be reviewed in the context of the actual application.

## Contributing

Bug reports, detection improvements, documentation fixes, and carefully scoped pull requests are welcome. Before contributing security-sensitive changes, read [`SECURITY.md`](SECURITY.md).
