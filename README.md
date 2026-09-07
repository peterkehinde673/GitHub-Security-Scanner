# GitHub Security Scanner

<p align="center">
  <img src="./image.png" alt="GitHub Security Scanner — secrets, SAST, dependency and security configuration scanning" width="100%">
</p>

<p align="center">
  <a href="https://github.com/peterkehinde673/GitHub-Security-Scanner/actions/workflows/ci.yml"><img src="https://github.com/peterkehinde673/GitHub-Security-Scanner/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github-security-scanner.onrender.com/"><img src="https://img.shields.io/badge/Live%20Scanner-Open-blue?logo=render" alt="Live Scanner"></a>
  <a href="https://github.com/marketplace/actions/github-security-scanner"><img src="https://img.shields.io/badge/GitHub%20Action-Marketplace-blue?logo=githubactions" alt="GitHub Action Marketplace"></a>
</p>

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
