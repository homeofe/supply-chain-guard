# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 6.x     | :white_check_mark: |
| 5.x     | :white_check_mark: |
| 4.x     | :x:                |
| 3.x     | :x:                |
| 2.x     | :x:                |
| 1.x     | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in supply-chain-guard, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **emre.kohler@elvatis.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

This tool is designed to detect malicious patterns in code. If you find a way to bypass detection, that is considered a valid security report. We want to know about:

- False negatives (malware not detected)
- Ways to evade the scanner (obfuscation bypasses, pattern gaps)
- Vulnerabilities in the scanner itself (e.g., ReDoS in patterns)
- Supply-chain risks in our own dependencies
- Correlation engine bypasses (findings that should link but don't)

## Known open findings

These scanner alerts on this repository are open on purpose, and why:

- **OpenSSF Scorecard: Branch-Protection and Code-Review.** `main` requires
  pull requests and green required checks, and administrators are not exempt.
  It does not require an approving review, because the project has a single
  maintainer and a required approval would block every merge. Both checks stay
  below the maximum until a second maintainer can review.
- **Dependabot alerts in `.github/publish-toolchain/`, and Scorecard's
  Vulnerabilities check, which counts them.** They concern dependencies that
  npm itself bundles (`undici`, `ip-address`, `brace-expansion`,
  `http-cache-semantics`). Bundled dependencies cannot be overridden, and no
  npm release ships fixed versions yet, so the alerts stay open rather than
  being dismissed. That npm runs only inside the release job. Its audit gate
  fails on high severity, and `.github/publish-toolchain/audit-exceptions.json`
  lists each high-severity advisory with a reason and an expiry date, so the
  gate fails again when the expiry passes.

## Recognition

We appreciate responsible disclosure and will credit reporters in our release notes (unless you prefer to remain anonymous).
