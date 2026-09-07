# Contributing

Thanks for your interest in GitHub Security Scanner.

## Before opening an issue

- Search existing issues first.
- For security vulnerabilities, follow `SECURITY.md` instead of posting sensitive details publicly.
- For false positives or missed detections, include a minimal reproducible example when it is safe to do so.

## Development

1. Fork the repository.
2. Create a focused branch for your change.
3. Keep changes small and security-focused.
4. Run the test suite, type-check, and production build before opening a pull request.
5. Update documentation when behavior or configuration changes.

## Pull requests

Please explain:

- What changed and why.
- How the change was tested.
- Any security or compatibility implications.

Do not include real secrets, credentials, private repository content, or other sensitive data in issues, tests, commits, or pull requests.

## Scope

The scanner intentionally uses bounded, static analysis. Contributions should preserve the project's safety boundaries, including resource limits, input validation, and the rule that scanned repository code is never executed.
