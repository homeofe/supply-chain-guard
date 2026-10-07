# Security audit report - 2026-10-07

## Scope and evidence

This review covers `supply-chain-guard` 6.5.1 (`main` at
`49e003420725490fdcf23cc5ac033296d62d5561`) in eleven areas: archive
extraction, reading extracted files, network downloads, feed and catalog
integrity, process execution, credential leakage into reports, the MCP server,
configuration that the scanned tree controls, regular-expression and parser
cost, integrity verification of downloaded artifacts, and the CLI output paths
and GitHub Action.

Two classes of defect were in scope:

- **Vulnerabilities in the scanner itself.** The scanner's input is hostile by
  definition, since a malicious package is the thing being scanned.
- **Detection evasion.** A malicious target that makes the scanner report a
  clean result, or less than it should, without marking the scan partial. For
  this tool a silent false negative is a security defect.

Every finding was reproduced against a build of 6.5.1 with synthetic fixtures;
no real malware was used. Domains in fixtures are reserved test names. The
findings are numbered F1 to F40 in the order of the original review.

All 40 findings are fixed in 6.5.2. Each fix has a regression test that runs
through the real entry point (`scan()`, the npm and PyPI walkers, the MCP
message handler, the install guard) and was shown to fail with the fix removed
and pass with it restored.

Advisories published with this release:

| Advisory | Findings | Summary |
|---|---|---|
| [GHSA-cq59-vmg7-pmqv](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-cq59-vmg7-pmqv) | F1, F29 | Windows: a tool planted in the scanned directory ran during a scan |
| [GHSA-wrr5-263w-wvmh](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-wrr5-263w-wvmh) | F2 | A policy file or inline comment inside the scanned tree could suppress the scanner's own findings |
| [GHSA-frvv-hf2w-gwf7](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-frvv-hf2w-gwf7) | F3 | A deny-list regex in a policy file inside the scanned tree could hang the scan |
| [GHSA-hpmp-48p8-f32h](https://github.com/homeofe/supply-chain-guard/security/advisories/GHSA-hpmp-48p8-f32h) | F11 | MCP server: `scan_directory` accepted network (UNC) paths and blocked the server |

## Findings and fixes

### Vulnerabilities

| ID | Severity | Finding | Fix |
|---|---|---|---|
| F1 | critical | On Windows, `scan` ran a `git.bat`, `git.cmd` or `git.exe` placed in the scanned directory, because tools were started by bare name and Windows searches the current directory before `PATH`. | Every external tool is resolved to an absolute path from absolute `PATH` entries only and started without a shell (`src/safe-exec.ts`). |
| F3 | high | A deny-list regex with overlapping alternation in a tree policy file hung the scan. | Tree-supplied patterns are limited to a safe subset; others are refused and the scan is marked partial. |
| F9 | medium | The tar preflight validated a different member path or link target than the system `tar` extracted. | Tar and ZIP members are written by the scanner itself, exactly as validated; links are never created. ZIP members are also checked against their CRC-32. |
| F11 | medium | MCP `scan_directory` accepted UNC paths (an outbound SMB connection on Windows) and one slow call blocked all others. | Network paths are refused before use; only scan calls are serialised; scan calls time out. |
| F16 | medium | The catalog cache was written non-atomically and through links. | Atomic write through a temporary file; a symlinked, junctioned or hard-linked target is refused. |
| F24 | low to medium | MCP tool results returned matched secrets verbatim. | Secret-category matches are redacted. |
| F26 | low | One very long stdin line ended the MCP server. | A chunked reader drops oversized lines and answers with a JSON-RPC error. |
| F27 | low | The MCP unknown-argument guard accepted prototype property names. | `Object.hasOwn`. |
| F29 | low to medium | The install guard ran `npm.cmd` from the current directory on Windows. | The package manager is resolved like every other tool. |
| F30 | low | A line break in a guarded argument truncated the `cmd.exe` command line. | Arguments containing CR or LF are refused before anything is started. |
| F36 | low | The threat feed had no integrity anchor, no rollback protection, and its age came from the client clock. | The feed is signed with Ed25519 at release and verified on refresh and on every cache load; rollback, shrink and future-date refreshes are refused. |
| F37 | low | The OSV verdict cache was trusted from disk. | Strict validation on load, ownership and permission checks on POSIX, and a short lifetime for cached negative answers. |
| F39 | low | A git remote with a credential-shaped path segment reached reports; SARIF fell back to the local path. | Credential-shaped remotes are dropped; SARIF omits provenance when there is no public remote. |

### Detection evasion

| ID | Severity | Finding | Fix |
|---|---|---|---|
| F2 | high | A `.scg.yml` or `scg-ignore-next-line` comment inside the scanned tree disabled the rules matching its own payload. | Not applied for cloned GitHub repositories and MCP scans; on local scans every suppressed high or critical finding is reported (`POLICY_SUPPRESSED_SEVERE`, `riskLevelBeforePolicy`). |
| F4 | high | A UTF-8 BOM or unparseable byte in `package.json` dropped every install-hook finding. | BOM stripped; an unparseable root manifest marks the scan partial. |
| F5 | high | The test-file exemption hid critical payloads in test-shaped paths. | Critical rules apply in test paths; separator-prefixed name forms removed. |
| F6 | high | A file named like one of the scanner's own modules, or a `.txt` file, was exempt from 71 rules. | Name-based exemption removed; the scanner's own files are recognised by exact path and content digest; `.txt` is not a document for critical rules. |
| F7 | high | `node_modules`, `venv` and similar directories were never walked, with no coverage signal. | Bundled and hook-referenced packages are walked; other excluded directories holding source are reported. |
| F8 | high | Executable but unlisted extensions were never read, although `require("./a.txt")` runs the file. | Files loaded by `require`/`import` are read; `.pth`, `.vbs`, `.wsf`, `.hta`, `.jse` and `.html` are read. |
| F10 | medium | UTF-16 source files were decoded as UTF-8, so every rule went blind. | UTF-16 is detected and decoded. |
| F12 | medium | The MCP config scanner missed packages behind `cmd /c`, `sh -c`, `pnpm dlx`, flag values and version ranges. | Launchers unwrapped, flag values skipped, ranges matched against pinned bad versions. |
| F13 | medium | An empty `mcpServers` key hid the `servers` list. | Both keys are read. |
| F14 | medium | An MCP config with a BOM was skipped. | BOM stripped; a config that does not parse marks the scan partial. |
| F15 | medium | Any file named `feed.json` anywhere was exempt from every scanner. | Only this project's own byte-identical `feed.json` is exempt. |
| F17 | medium | A broken, mismatched, unreadable or deleted catalog never marked the scan partial. | Broken, replaced or deleted catalogs are high and partial; a catalog that was never downloaded, or one built for the previous release, stays informational. |
| F18 | medium | `--since` scans skipped changed files with non-ASCII names. | NUL-separated, unquoted git output; an unresolvable changed path marks the scan partial. |
| F19 | medium | The install guard read several real command lines as containing no package. | Per-manager value flags; `it`, `link`, `exec`, `dlx` and `x` are checked. |
| F20 | medium | Files over 5 MiB with an unread extension skipped the known-malware digest check. | Hashed up to 64 MiB; larger files are reported. |
| F21 | medium | Lockfile integrity values were prefix-tested; sha1-only and garbage values passed. | Parsed by algorithm, base64 and exact length; sha1-only is reported. |
| F22 | medium | `process["env"]`, escaped identifiers and aliases defeated the exfiltration rules. | A light normalisation pass for these rules; a new rule for `exec` of a download piped into a shell. |
| F23 | medium | `package.json` under test or fixture paths skipped the install-hook checks even when referenced by the root. | Referenced manifests (`file:`, `link:`, workspaces) are checked. |
| F25 | low | The MCP plain-HTTP endpoint check worked on the raw string. | Decided on the parsed URL; `ws:` is flagged too. |
| F28 | low | Prompt-injection collection skipped arrays and deeper nesting. | All string values are visited, with a node cap. |
| F31 | low to medium | A lookalike registry host in a lockfile was graded low. | Graded high (`DEPENDENCY_UNTRUSTED_SOURCE`). |
| F32 | low | The governance check threw on a non-string `resolved` and ignored lockfile v1. | Type checks; v1 dependencies walked. |
| F33 | low | SLSA attestations were accepted on structure alone. | Digests validated and compared with the artifact; every attestation is reported as not signature-verified. |
| F34 | low | A malformed strong npm integrity token let a weaker one decide. | Any malformed known-algorithm token fails verification. |
| F35 | low | A PyPI digest mismatch was reported only as a generic info finding. | A distinct high `ARTIFACT_DIGEST_MISMATCH`. |
| F38 | low | npm cache keys folded case. | Keys use each registry's own name normalisation. |
| F40 | low | The MCP tool advertised `since: "HEAD~1"`, which the diff scanner rejected. | One shared ref guard; `HEAD~1` and `HEAD^` are accepted. |

## Decisions recorded with the fixes

- **Policy files and inline comments.** Local projects use them to record
  reviewed false positives, so a local scan still honours them; the report now
  shows what they removed. Scans of a cloned repository and MCP scans do not
  apply them for high or critical findings.
- **Catalog after an upgrade.** A cached catalog built for the previous release
  is the normal state right after an upgrade and is not a partial scan; one
  `feed refresh` replaces it.
- **Large non-code files.** A file past the 64 MiB hashing limit is reported as
  information, not as a partial scan, because large media assets are ordinary.
- **Shell installers.** A `.sh` file piping `curl` into `sh` is not flagged:
  legitimate installers do exactly that.
- **SLSA level.** The level still reflects build configuration; the report says
  that no signature was verified.
- **Feed source.** `feed refresh` downloads the signed feed from the latest
  release, so threat intel merged between two releases reaches refresh users
  with the next release. Releases have been near-daily (26 in the 31 days
  before this audit). Only the highest release is marked `latest`, and a
  client falls back to the newest signed release if `latest` has no feed.

## Verification

- Full test suite on Linux, the repository self-scan at `--fail-on critical`,
  and the build gates, on the final tree.
- A new CI job runs the tool-lookup, install-guard and archive tests on a
  Windows runner, because the Windows lookup rule behind F1 does not exist on
  Linux.
