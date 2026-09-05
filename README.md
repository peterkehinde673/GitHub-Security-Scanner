# GitHub Security Scanner & Vulnerability Analyzer

A modular, high-performance security scanner and code analyzer designed to scan public GitHub repositories for hardcoded secrets, dangerous code patterns (SAST), software supply-chain vulnerabilities, and infrastructure misconfigurations with deterministic scoring and automated remediation suggestions.

---

## 🛡️ Security Engine Architecture

The scanner operates entirely without executing untrusted repository code. It processes files through isolated static analysis modules:

1. **Secret Scanner (`backend/scanner/secrets/`)**:
   - Regex and entropy-based identification for AWS keys, GitHub tokens, OpenAI keys, Slack webhooks, Private keys, JWT tokens, and database connection strings.
   - Shannon Entropy verification with false-positive suppression for mock/sample tokens and documentation placeholders.
   - Automated evidence masking (e.g. `AKIA****************`) to protect secrets in reports.

2. **Code Pattern Scanner / SAST (`backend/scanner/code-patterns/`)**:
   - OWASP Top 10 detection covering SQL Injection, OS Command Injection, React XSS (`dangerouslySetInnerHTML`), Path Traversal, Insecure Python Deserialization (`pickle`), and Disabled TLS verification (`rejectUnauthorized: false`).

3. **Dependency & Supply Chain Scanner (`backend/scanner/dependencies/`)**:
   - Manifest parsers for `package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`, `pom.xml`, and `Gemfile`.
   - Identification of wildcard versions (`*`), unpinned requirements, and curated known CVE advisory cross-referencing (e.g. prototype pollution, log4j patterns).

4. **Configuration & Infrastructure Scanner (`backend/scanner/configuration/`)**:
   - Security auditing for Dockerfiles (root user execution), production debug flags, permissive CORS headers (`*`), and committed `.env` secrets.

5. **Deterministic Scoring Engine (`backend/scanner/scoring/`)**:
   - Mathematical penalty deduction: Critical (-25 pts), High (-15 pts), Medium (-8 pts), Low (-3 pts).
   - Grade boundaries (A+, A, B, C, D, F) with clean code baseline (100 pts) and floor at 0.

---

## 🔒 Security Hardening & Defenses

The application implements defense-in-depth security hardening across API boundaries:

1. **Strict Input Boundaries & Payloads**:
   - `/api/scan` limits: Maximum 200 files per scan, 500 KB per individual file (calculated via actual UTF-8 byte length), and 10 MB total scan payload ceiling.
   - Request body parser ceiling set to 12 MB with safe JSON error boundaries.
2. **Logical Path Traversal Protection**:
   - All file paths are strictly validated before normalization. Absolute paths (`/`, `\`), Windows drive prefixes (`C:\`), directory traversal sequences (`../`, `..\`), and null bytes (`\0`) are immediately rejected.
3. **Duplicate Path Deduplication**:
   - Identical logical file paths are safely deduplicated to the first valid occurrence, preventing CPU and memory exhaustion attacks.
4. **Outbound GitHub Fetch Protections**:
   - 10–12 second timeout limits on all outbound GitHub metadata, tree, and raw file fetches.
   - Git tree processing capped at 10,000 items with graceful handling of malformed nodes.
   - Bounded concurrency worker pool (6 simultaneous downloads) preventing socket starvation.
   - Per-file streaming byte-size ceiling (500 KB) aborting oversized downloads early.
5. **In-Memory Rate Limiting**:
   - Single-instance in-memory rate limiting keyed by client IP with automated 60-second window expiration.
   - Default: 30 requests/min for expensive scan/fetch/chat routes, 60 requests/min for metadata routes. Health check remains responsive.
6. **Configurable CORS & Information Disclosure Safeguards**:
   - Environment-driven `CORS_ORIGIN` allowlisting (same-origin default in production).
   - Safe error handling (`sendSafeError`) preventing exposure of internal stack traces, filesystem paths, or credentials.

---

## 🧪 Authoritative Test Architecture (`node:test`)

The project uses a single authoritative test suite defined with standard `node:test` (`describe`/`it`) and `node:assert` across `tests/*.test.ts`:

- `tests/secrets.test.ts` (6 tests: AWS, GitHub tokens, OpenAI keys, masking, placeholder suppression, Shannon entropy)
- `tests/patterns.test.ts` (5 tests: SQL injection, OS command injection, React XSS, Python pickle deserialization, disabled TLS)
- `tests/dependencies.test.ts` (4 tests: package.json wildcards, requirements.txt pinning, Cargo.toml wildcards, CVE advisories)
- `tests/configuration.test.ts` (4 tests: Dockerfile root user, debug mode, permissive CORS, committed `.env` secrets)
- `tests/scoring.test.ts` (3 tests: clean baseline scoring, critical deduction calculation, score flooring/grading)
- `tests/security-hardening.test.ts` (19 tests: limits on file count, oversized files, total payload size, malformed objects, absolute paths, traversal, Windows traversal, null bytes, duplicate deduplication, maxFiles clamping, tree filtering, rate limiting, rate limiter expiration, CORS, error disclosure, target metadata, Git ref validation, legitimate file scans, repository query formats)

**Total: 41 tests across 6 suites (100% passing).**

---

## 🚀 Commands & Verification

### 1. Run Authoritative Test Suite
Executes all 41 `describe`/`it` tests directly via `node:test`:
```bash
# Node.js / Linux / Render CI
npm test

# Bun runtime
bun test
```

### 2. Type Checking & Linting
Type-checks the full TypeScript codebase:
```bash
npm run lint
```

### 3. Build Production Bundle
Builds the Vite client-side bundle and compiled server:
```bash
npm run build
```

### 4. Start Development Server
```bash
npm run dev
```

---

## ⚙️ Environment Variables

See `.env.example` for reference:
- `GEMINI_API_KEY`: Google GenAI API key for the AppSec Copilot.
- `GITHUB_TOKEN`: Optional GitHub personal access token for higher API rate limits.
- `CORS_ORIGIN`: Allowed origins (e.g. `https://my-app.onrender.com,https://example.com`). Defaults to permissive in dev and strict same-origin in production.
- `RATE_LIMIT_WINDOW_MS`: Rate limiting window in milliseconds (default: `60000`).
- `RATE_LIMIT_MAX_REQUESTS`: Rate limiting maximum requests per window (default: `60`).
