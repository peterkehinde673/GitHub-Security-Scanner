# Security Policy

## Supported deployment

Security issues in the GitHub Security Scanner web service, scanner engine, or GitHub Action are welcome.

The hosted scanner currently targets **public GitHub repositories** and is designed to treat repository content as untrusted input.

## Reporting a vulnerability

Please avoid publishing sensitive vulnerability details in a public GitHub issue before a fix is available.

For a responsible disclosure, use GitHub's private vulnerability reporting feature if it is enabled for this repository. Otherwise, contact the repository maintainer privately through the contact method available on the maintainer's GitHub profile.

When reporting, include:

- A clear description of the vulnerability.
- The affected component or endpoint.
- Reproduction steps or a minimal proof of concept, where safe.
- The potential security impact.
- Any suggested mitigation.

Do not include real secrets, access tokens, private repository contents, or other sensitive credentials in the report.

## Scope

Examples of issues worth reporting include:

- Authentication or authorization bypasses.
- Server-side request forgery or unsafe outbound fetching.
- Remote code execution or unintended code execution.
- Path traversal or arbitrary file access.
- Cross-site scripting or injection vulnerabilities.
- Secret or credential disclosure caused by the scanner.
- Rate-limit bypasses that can materially affect service availability.
- Prompt-injection paths that cause the AppSec Copilot to disclose protected information or perform unintended privileged actions.

False positives or missed detections in the static-analysis rules are useful bug reports, but they are generally not security vulnerabilities in the scanner itself.

## Safe testing

Only test against repositories and systems you are authorized to test. Do not submit real credentials or intentionally harmful payloads to the hosted service.
