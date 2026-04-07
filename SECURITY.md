# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
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

## Recognition

We appreciate responsible disclosure and will credit reporters in our release notes (unless you prefer to remain anonymous).
