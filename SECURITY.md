# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 6.x     | :white_check_mark: |
| 5.x     | :x:                |
| 4.x     | :x:                |
| 3.x     | :x:                |
| 2.x     | :x:                |
| 1.x     | :x:                |

Security fixes ship in the newest 6.x release only. 5.x received none of the
fixes for the advisories below, so it is no longer supported.

## Published security advisories

Every advisory below is fixed in 6.6.0. Upgrade to 6.6.0 or later.

| Advisory | Severity | Affected | Fixed in | Summary |
|---|---|---|---|---|
| [GHSA-77wv-pr2j-p38h](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-77wv-pr2j-p38h) | low | <= 6.5.6 | 6.5.7 | A crafted version range in an MCP config can stall a scan |
| [GHSA-gqpg-9mjx-pv4w](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-gqpg-9mjx-pv4w) | high | <= 6.5.5 | 6.5.6 | npx: a tool planted in `node_modules/.bin` of the scanned directory runs during the scan |
| [GHSA-cq59-vmg7-pmqv](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-cq59-vmg7-pmqv) | high | <= 6.5.1 | 6.5.2 | Windows: a scan executes a `git` binary planted in the scanned directory |
| [GHSA-wrr5-263w-wvmh](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-wrr5-263w-wvmh) | medium | <= 6.5.1 | 6.5.2 | A policy file or inline comment inside the scanned tree can suppress the scanner's own findings |
| [GHSA-frvv-hf2w-gwf7](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-frvv-hf2w-gwf7) | medium | <= 6.5.1 | 6.5.2 | A deny-list regex in a policy file inside the scanned tree can hang the scan |
| [GHSA-hpmp-48p8-f32h](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-hpmp-48p8-f32h) | medium | <= 6.5.1 | 6.5.2 | MCP server: `scan_directory` accepts network (UNC) paths and blocks the server |
| [GHSA-pvhm-wc2r-q627](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-pvhm-wc2r-q627) | low | < 6.3.0 | 6.3.0 | `WORKFLOW_SECRET_TO_UPLOAD_PATH` judged the spelling of a secret reference, not its exposure |

The GitHub Action pins the exact scanner version it installs, so a workflow
on `uses: homeofe/supply-chain-guard@v6` runs the newest 6.x release.

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

## Feed integrity

`feed.json`, the threat feed that `supply-chain-guard feed refresh` downloads, is
signed with Ed25519, and the signature (`feed.json.sig`) is published next to it.
`feed refresh` reads the daily feed channel on GitHub Pages by default, signed by
the `sign` job of `.github/workflows/feed-daily.yml`, and falls back to the
feed attached to the latest GitHub Release, signed by the release job. Both use
the same key. The public key is compiled into the package
(`src/feed-signing-key.ts`); the private key is a GitHub Actions secret
available only to those two jobs.
`feed refresh` refuses any feed whose signature does not verify against that key,
and every scan re-verifies the cached copy.

Key fingerprint: the SHA-256 of the DER SPKI encoding of the public key starts
with `91b2c7d7d50612a3`. Compare it with
`openssl pkey -pubin -in key.pem -outform DER | sha256sum` on the PEM in
`src/feed-signing-key.ts`. A different fingerprint in a release means the key was
rotated or the package was altered; report it as a vulnerability.

`--allow-unsigned-feed` turns the check off for a mirror that cannot be signed.
Use it only for a source you control.

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
  npm itself bundles, and only an npm release can fix them, because bundled
  dependencies cannot be overridden. Open on 2026-10-24: `undici`
  GHSA-xjj6-f33q-929c (high; inside npm only `node-gyp` uses it, for native
  builds, which the release job does not run) and `ip-address`
  GHSA-rxp7-6hxx-x8q5 (medium; inside npm only `socks` uses it, for proxy
  connections, which the release job does not open). The newest npm 11.x does
  not ship either fix yet, so the alerts stay open rather than being
  dismissed. That npm runs only inside the release job. Its audit gate
  fails on a high-severity advisory as soon as a newer npm of the same major
  no longer reports it, and names that release so the pin can move. Until then
  the advisory is a warning on the job. A critical advisory always fails unless
  `.github/publish-toolchain/audit-exceptions.json` lists it with a reason and
  an expiry date, and the gate fails again when that expiry passes.

## Recognition

We appreciate responsible disclosure and will credit reporters in our release notes (unless you prefer to remain anonymous).
