# Changelog

All notable changes to supply-chain-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The latest release is at the
top; release tags trigger the CI publish pipeline (npm via OIDC + GitHub Release + `v5` branch).

## [Unreleased]

## [5.17.6] - 2026-07-20
**Threat intel: SleeperGem - three malicious RubyGems releases backdoor developer machines**

Added detection for SleeperGem (StepSecurity and Aikido, reported by The Hacker
News on 2026-07-20). Malicious releases of three gems were published to
RubyGems.org between 2026-07-18 and 2026-07-19. Each release is a loader: it
pulls a second stage (`deploy.sh` plus a native binary) from an attacker account
on a public Forgejo instance, checks roughly thirty CI environment variables
(`GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI` and similar) and exits if any is set,
so it only detonates on developer laptops. On a developer machine it drops a
native daemon, installs cron and systemd-user persistence, and - where
passwordless sudo is available - plants a setuid root copy of the system shell
disguised as a networking utility.

Two of the three gems are long-lived legitimate packages that lay dormant for
years before receiving the malicious update, so their indicators are pinned per
version: a bare-name indicator would flag every clean install. Only
`git_credential_manager`, which impersonates Microsoft's Git Credential Manager
and has no legitimate history, is anchored by name.

### Added
- Version-pinned `ruby:` package FeedIOCs in `BUNDLED_FEED` (src/threat-intel.ts)
  for `git_credential_manager` 2.8.0-2.8.3, `Dendreo` 1.1.3-1.1.4 and
  `fastlane-plugin-run_tests_firebase_testlab` 0.3.2. The RubyGems scanner
  resolves these against `Gemfile` and `Gemfile.lock`.
- `url` FeedIOC for the second-stage payload path
  `git[.]disroot[.]org/git-ecosystem`. The bare host is deliberately NOT added to
  `KNOWN_C2_DOMAINS`: it is a legitimate public Forgejo instance and blocking it
  wholesale would flag every project that legitimately hosts code there.
- `^git_credential_manager$` to `MALICIOUS_PACKAGE_PATTERNS` (src/patterns.ts).
- `SLEEPERGEM_PAYLOAD_HOST` and `SLEEPERGEM_SETUID_SHELL` campaign patterns
  covering the attacker Forgejo path and the `/usr/local/sbin/ping6` setuid drop.
  The daemon directory `~/.local/share/gcm` is intentionally not a signature: the
  real Git Credential Manager uses it too.
- `SleeperGem RubyGems releases (July 2026)` describe block to
  `src/__tests__/campaigns.test.ts`, including a negative test asserting that
  clean versions of the two hijacked real gems are not flagged.

## [5.17.5] - 2026-07-19
**Threat intel: NadMesh botnet - Go-based botnet hunting exposed AI services**

Added detection for the NadMesh botnet (XLab, reported by The Hacker News on
2026-07-17). NadMesh is a Go-based botnet that scans for exposed AI services
(Ollama, vLLM and similar) and CI/CD hosts, harvesting AWS keys and Kubernetes
tokens; its operator claimed 3,811 unique AWS keys. Detection rides on XLab's
published network infrastructure plus the agent-sample hash - there are no
package IOCs because this is a scanning botnet rather than a poisoned registry
package.

### Added
- Command-and-control domain `cdnorigin[.]net` to `KNOWN_C2_DOMAINS` and as a
  `domain` FeedIOC in `BUNDLED_FEED` (src/threat-intel.ts).
- Command-and-control IP `209[.]99[.]186[.]235` to `KNOWN_C2_IPS` and as an `ip`
  FeedIOC.
- Agent-sample SHA1 `31c69b3e12936abca770d430066f379ec1d997ec` to
  `KNOWN_MALICIOUS_HASHES` and as a `hash` FeedIOC. XLab published a SHA1 (not
  MD5/SHA256); it is stored as a content-reference indicator, matched by the
  same substring check as the existing Git-SHA entry.
- `NadMesh botnet (July 2026)` describe block to `src/__tests__/campaigns.test.ts`
  asserting the domain, IP and hash each produce a critical finding.

## [5.17.4] - 2026-07-18
**Fix: `scan --format json` and risk-history reported a stale tool version (v5.2.0)**

### Fixed
- `src/scanner.ts` hardcoded `TOOL_VERSION = "5.2.0"`, so `ScanReport.tool` (emitted
  verbatim by the JSON reporter) and the persisted `.scg-history/` risk entries reported
  `supply-chain-guard v5.2.0`, while every other surface (text header, SARIF, SBOM, HTML
  footer, GitLab) correctly used reporter.ts's own version. Corrected to the release version.

### Changed
- `check:version-sync` now also covers `src/scanner.ts`, so `TOOL_VERSION` can never drift
  undetected again - the root cause was that the gate did not include scanner.ts.

## [5.17.3] - 2026-07-18
**Threat intel: ViteVenom - malicious Vite npm packages with blockchain C2**

Added detection for the ViteVenom campaign (Checkmarx, reported by The Hacker
News on 2026-07-18). Threat actor "SuccessKey" - an expansion of the earlier
ChainVeil campaign - published seven scoped npm packages (2026-06-29 to
2026-07-03) that impersonate the "@vitejs/*" namespace to look legitimate. The
malicious code executes at IMPORT time rather than install time to limit
endpoint detection, and delivers a RAT (reverse shell, credential harvesting,
file exfiltration, persistent backdoor) via a four-tier blockchain command-and-
control spanning Tron, Aptos and BNB Smart Chain.

- Added the seven fully-malicious package names as bare-name package IOCs to
  BUNDLED_FEED (src/threat-intel.ts): @uw010010/vite-tree, @vite-tab/tab,
  @vite-ln/build-ts, @vite-mcp/vite-type, @vite-pro/vite-ui, @vitets/vite-ts,
  @vite-ts/vite-ui. These drive both the directory-scan MALICIOUS_DEPENDENCY
  finding and the install-guard block, on any version.
- Pinned the same seven names explicitly in MALICIOUS_PACKAGE_PATTERNS
  (src/patterns.ts) for traceable name-based signatures.
- Added a "ViteVenom Vite npm packages (July 2026)" describe block to
  campaigns.test.ts (name-match, @vitejs false-positive guard, directory-scan,
  and install-guard coverage).
- No wallet/contract addresses were published in extractable form, so none were
  ingested (a guessed address protects nobody and risks false positives).

## [5.17.2] - 2026-07-17
**Fix: a globally-installed binary flagged supply-chain-guard's OWN repo (~600 false positives)**

Reported by a user who ran `npm install -g supply-chain-guard` and then
`supply-chain-guard scan .` on a checkout of this repository, and got ~597
THREAT_INTEL / IOC matches. This was a FALSE POSITIVE, not a compromise: the
scan was matching the tool's own threat database (the malicious domains, IPs,
hashes and package names that src/threat-intel.ts, src/ioc-blocklist.ts and the
test fixtures carry by design).

Root cause: the self-scan suppression that stops the tool from flagging its own
IOC-definition files keyed ONLY on the scanned path equalling the running
binary's installed package root (isOwnPackageRoot). That is true for
`node dist/cli.js` run from the repo (self-scan 0/0), but NOT for a globally
installed binary scanning a separate checkout - so the guard silently no-opped
and the scanner flagged its own signatures.

Fix: the checkout is now ALSO recognized by its package.json identity (name
"supply-chain-guard" AND repository pointing at homeofe/supply-chain-guard), so
a checkout scans clean no matter how the tool was installed. Gated against
spoofing: the recognition unlocks only the narrow IOC-string suppression for the
exact files in the known self-source allowlist; the malware/obfuscation pattern
checks still run on every file, so a hostile project cannot hide a payload by
forging the name. 3 regression tests including the spoof case.

## [5.17.1] - 2026-07-17
**MCP registry metadata + honest package description**

- Added `mcpName` to package.json and a `server.json` so the MCP server can be
  published to the official MCP registry (registry.modelcontextprotocol.io),
  from which PulseMCP / Glama / mcp.so ingest automatically. server.json's
  version is now covered by the check:version-sync gate so it cannot drift out
  of sync with the published package.
- Corrected the package.json description to match the README: "grades SLSA
  provenance (in-toto/DSSE structural validation)" instead of the old "verifies
  SLSA provenance" (the overclaim fixed in v5.15.0 - the npm description still
  carried the stale wording).

## [5.17.0] - 2026-07-17
**OSV-format feed export + adopter badge (ecosystem reach)**

- `supply-chain-guard feed osv` exports the feed's malicious-package indicators
  as [OSV-schema](https://ossf.github.io/osv-schema/) records (npm, Go, RubyGems,
  Packagist, crates.io, NuGet), so the feed is consumable by osv-scanner and
  other OSV-native tooling and is shaped toward ossf/malicious-packages. Bare
  names export as an all-versions range; pinned name@version as a specific
  version; domain/IP/URL/hash IOCs and non-OSV ecosystems (e.g. Jenkins) are
  skipped. Deterministic output (ids + timestamps derive only from the entry).
  `--out <file>` writes to a file; new module src/osv-export.ts (toOsvRecords /
  parsePackageValue, both exported from the library API).
- A "scanned by supply-chain-guard" adopter badge in the README that projects
  running the scanner in CI can add to their own README.

## [5.16.0] - 2026-07-17
**Starjacking detection (repository-claim corroboration)**

Completes the differentiators track: in `npm <pkg>` mode the scanner now
corroborates a package's claimed source repository, catching the borrowed-trust
pattern where a malicious package points `repository` at a popular project it
does not own to inherit that project's stars and trust scores.

- New rule `STARJACKING_SUSPECTED` (medium): fetches the claimed GitHub repo's
  root package.json and flags ONLY the high-confidence case - the repo publishes
  a different, unrelated package and is not a monorepo containing this one.
- Deliberately conservative (this is a false-positive-sensitive check, so every
  ambiguous or benign case is skipped, never flagged): non-GitHub hosts, a
  `repository.directory` subdir, a package scope matching the repo owner, a repo
  that declares `workspaces` / is marked `private` / has a pnpm-workspace.yaml or
  lerna.json (all monorepo signals), an unfetchable/private repo, matching or
  token-related names, and names too generic to judge. The repo fetch is bounded
  by a 10s timeout and the 5 MB size limit and never throws.
- An adversarial gate over the diff caught (and this release fixes) the dominant
  false-positive path: monorepo detection originally read only the package.json
  `workspaces` key, so pnpm/lerna/nx monorepos (and all-generic package names
  like `@x/core`) were mis-flagged. Hardened with scope-owner ownership, private-
  root, generic-name, and workspace-manifest guards.

## [5.15.0] - 2026-07-17
**Honest SLSA provenance validation (fixes an overclaim)**

The SLSA verifier previously treated a file merely NAMED provenance.json as
proof of provenance - a present-but-empty `{}` scored Level 3, and the README
claimed it "verifies SLSA provenance". It now actually parses and structurally
validates the attestation (R4 of the gap-analysis push, provenance half).

- `parseAttestation` reads the attestation and validates it as an in-toto
  Statement / DSSE envelope (base64 payload) / Sigstore bundle, requiring a real
  SLSA predicate type and at least one digested subject. A present-but-empty or
  malformed provenance file no longer inflates the SLSA level, and a public key
  (cosign.pub) no longer counts as a provenance statement.
- New rule `SLSA_PROVENANCE_INVALID` (medium): a provenance file that is present
  but is not usable SLSA provenance (placeholder/garbage, or a SLSA statement
  with no digested subject) - it gives a false sense of verifiability. A valid
  NON-SLSA in-toto attestation (e.g. an SBOM/SPDX attestation) is recognized as
  legitimate and is NOT flagged.
- The attestation read is now bounded by the same 5 MB limit as every other
  scanner (a pathological multi-hundred-MB provenance file is skipped, not read
  into memory), and the unwrap chain is depth-bounded against crafted nesting.
- README updated to reflect what is actually verified: SLSA provenance GRADING
  via in-toto/DSSE structural validation (not full cryptographic
  signature/Rekor/Fulcio verification, which remains a documented follow-up).
- An adversarial review over the diff caught and this release fixes: the missing
  size bound, a false positive that flagged legitimate non-SLSA attestations as
  malformed, and a doubled phrase in the finding message.

## [5.14.0] - 2026-07-17
**Product/DX: path-scoped policy, JUnit output, MCP v2**

Closes the top product/DX gaps from the repo-wide gap analysis (R3 of the
4-track push).

- **Path-scoped policy + inline suppressions**: `.supply-chain-guard.yml` now
  supports `ignore:` path globs (pruned from the scan), per-path `suppress`
  entries (`rule` + optional `path:` glob; bare entries stay global), and inline
  `// scg-ignore-next-line RULE` / `# scg-ignore-next-line RULE` comments that
  suppress the finding on the next source line. A minimal built-in glob matcher
  keeps commander the only runtime dependency.
- **Fixed the dead `allowlist.domains` key**: it was parsed and documented but
  never read (`applyPolicy` only used `allowlist.packages`) - the exact silent
  no-op the v5.3 fail-closed philosophy exists to prevent. It now suppresses
  THREAT_INTEL_MATCH / IOC_KNOWN_C2_DOMAIN findings for an allowlisted domain or
  its subdomains. (`allowlist.githubOrgs` is honestly documented as parsed-but-
  not-yet-enforced with a startup note, rather than left silently dead.)
- **JUnit XML output** (`--format junit`) for native test-tab rendering in
  Jenkins/Azure DevOps/GitLab/CircleCI/Bitbucket, plus a general `-o, --output
  <file>` flag on `scan`.
- **MCP v2**: the compact report now carries `line` + `recommendation` (with a
  `maxFindings` param); `scan_directory` accepts a `since` commit for diff scans;
  `ioc_lookup` gained an `indicator` mode (look up a domain/url/ip/hash against
  the feed, not just a package name).
- **action.yml** no longer scans twice: JSON is only re-produced when the
  requested format is not already JSON.
- An adversarial gate over the diff caught (and this release fixes) a real
  false-negative: the glob matcher compiled `**/` to a bare `.*`, so
  `ignore: ["**/vendor.js"]` silently dropped lookalike files like
  `notvendor.js` from scanning (and per-path suppress over-suppressed them).
  `**/` now requires the path-segment boundary.

## [5.13.0] - 2026-07-17
**Detection coverage: Rust/Go/Python lockfiles + agent-memory files**

Closes the sharpest gap surfaced by a repo-wide gap analysis: several ecosystems'
IOCs already shipped in the feed but could never match because the resolved
dependency tree was never read.

- **Cargo.lock + go.sum** are now parsed and matched against the threat feed
  (new rules CARGO_MALICIOUS_CRATE, GO_MALICIOUS_MODULE) and checkBadVersion.
  Both files were already recognized but their resolved dependency trees were
  never opened - so the bundled crates.io / Go IOCs (e.g. the TrapDoor crates,
  BufferZoneCorp Go modules) could not fire. Proven end-to-end: a Cargo.lock or
  go.sum listing a known-bad crate/module now flags it.
- **Python lockfiles** poetry.lock, uv.lock, and Pipfile.lock are now scanned
  (new module python-lockfile-scanner.ts) - resolved packages run through the
  same KNOWN_BAD_PYPI_VERSIONS + feed matching as the other ecosystems. Pipenv
  custom category groups (docs/tests/ci, not just default/develop) are covered.
- **Agent-memory files** MEMORY.md, AGENTS_MEMORY.md, memory/*.md,
  .claude/memory/*.md and .specstory/**/*.md now flow through the skills-scanner
  prompt-injection / invisible-unicode pipeline. A poisoned memory file
  re-injects instructions on every agent session; it was previously unscanned.
- An adversarial gate over the diff caught (and this release fixes) a Pipfile.lock
  false negative: custom pipenv category groups were skipped, so a malicious
  package pinned under a custom category escaped detection.

## [5.12.4] - 2026-07-17
**Threat intel: PhantomSync (npm crypto stealer) + Pepesoft (NuGet surveillance)**

Two campaigns disclosed 2026-07-14/15, ingested with primary-source
verification. Both were confirmed genuinely new against the existing feed.

- **PhantomSync** (npm, Xygeni, 2026-07-15): a crypto-wallet stealer that
  exfiltrates ETH/BTC/Solana keys and BIP-39 seeds to IPFS via Pinata and
  persists via cron/schtasks/launchd. SINGLE-SOURCE (Xygeni only), so ingested
  at confidence 0.85. Eight generic blockchain-util package names published by
  solbuilder_io, each malicious at specific versions only, so version-pinned in
  KNOWN_BAD_NPM_VERSIONS + the bundled feed - never bare-name. Note base58-utils
  is malicious at 1.0.0 / 1.0.1 / 1.0.3 but NOT 1.0.2. The config dead-drop
  (a GitHub gist raw path) and three IPFS config-fallback CIDs added to
  KNOWN_DEAD_DROPS; the Pinata/IPFS gateway hosts are deliberately not blocked.
- **Pepesoft** (NuGet, Socket, 2026-07-14): a game-cheat surveillance suite
  (Telegram-controlled screenshots, host remote control). The 11 package IDs in
  the writeup carry a uniform "-x-x" suffix that is a source-side redaction
  placeholder, NOT an installable ID (a full mirror omits them), so NO package
  blocklist entries were ingested - a redacted ID blocks nothing and a guessed
  real ID risks false positives. Detection instead rides on the 31 primary-source
  SHA-256 payload hashes (KNOWN_MALICIOUS_HASHES) plus network infra: C2 sub-hosts
  calm-voice-9797[.]888c888x888[.]workers[.]dev, s3[.]ru-3[.]storage[.]selcloud[.]ru,
  bots[.]pepesoft[.]ru (KNOWN_C2_DOMAINS), proxy 196[.]16[.]3[.]71 (KNOWN_C2_IPS),
  and the Telegram/GitHub/HuggingFace/Discord-webhook paths (KNOWN_DEAD_DROPS).
  Specific sub-hosts/paths only - never the workers[.]dev / selcloud[.]ru /
  discord[.]com / huggingface[.]co apex.
- 7 new campaign tests incl. FP guards (clean base58-utils@1.0.2, the redacted
  NuGet ID is not blocked, legitimate workers[.]dev apex not flagged). feed.json
  regenerated (376 entries).

## [5.12.3] - 2026-07-16
**Threat-intel: AsyncAPI npm supply-chain compromise (July 2026)**

- Added IOCs for the AsyncAPI npm supply-chain attack (The Hacker News /
  BleepingComputer / Socket / StepSecurity, 2026-07-14 to 07-15). Five malicious
  versions across four packages in the `@asyncapi` namespace were published to
  npm during a roughly 4-hour window on 2026-07-14 (07:10-11:18 UTC) and
  delivered a credential-stealing multi-stage botnet loader. The loader pulls a
  second stage from IPFS and supports C2 over HTTP, Nostr relays, IPFS,
  BitTorrent DHT, libp2p GossipSub, and an Ethereum smart contract. All five
  versions have since been unpublished from npm. Reported jointly by OX Security,
  SafeDep, Socket, StepSecurity, Microsoft, Wiz and Aikido.
- Version-pinned entries added to `KNOWN_BAD_NPM_VERSIONS` and `BUNDLED_FEED`:
  `@asyncapi/generator@3.3.1`, `@asyncapi/generator-helpers@1.1.1`,
  `@asyncapi/generator-components@0.7.1`, and `@asyncapi/specs@6.11.2` /
  `6.11.2-alpha.1`. These are legitimate packages, so the bare names are
  intentionally NOT blocked - only the listed versions match.
- Added the specific IPFS second-stage CID as a dead-drop resolver. The exact
  malicious CID path is matched, never the `ipfs[.]io` gateway host, so
  legitimate IPFS usage is not flagged.
- New "AsyncAPI npm compromise (July 2026)" campaign test block.
- Source excerpts came from the arena.elvatis.com feed; the exact package
  versions were confirmed against two independent primary reports before being
  added.

## [5.12.2] - 2026-07-13
**Threat-intel: Injective Labs SDK npm compromise (July 2026)**

- Added IOCs for the Injective Labs SDK supply-chain attack (The Hacker News /
  BleepingComputer / Socket / Aikido, 2026-07-08 to 07-10). The Injective Labs
  SDK GitHub repo was compromised and its trusted-publisher (OIDC) pipeline
  abused to publish `@injectivelabs/sdk-ts@1.20.21` carrying "fake telemetry"
  that captures wallet private keys and mnemonic seed phrases when SDK key
  generation/import functions run, base64-encodes them, and HTTPS-POSTs to a
  lookalike exfil host. Version 1.20.21 was pinned across 17 dependent
  `@injectivelabs` scoped packages (18 total; ~310 downloads before it was
  deprecated). Clean version: 1.20.23.
- All 18 package entries are version-pinned (only 1.20.21 matches) - these are
  legitimate packages, so the bare names are intentionally NOT blocked.
- Added the fake-telemetry exfil domain (the full specific hostname is matched,
  never a broad `injective[.]network` block, so legitimate SDK endpoints are
  not flagged) and the two SHA-256 hashes of the infostealer files to
  `ioc-blocklist.ts` and `BUNDLED_FEED`, plus a campaign test block.
- Source excerpts came from the arena.elvatis.com feed; the exact indicators
  were confirmed against the linked primary reports before being added.

## [5.12.1] - 2026-07-12
**Threat-intel: jscrambler npm compromise (July 2026)**

- Added a bundled-feed IOC for the compromised `jscrambler@8.14.0` npm release,
  which shipped a malicious preinstall hook that drops a Rust-based infostealer
  during install (arena.elvatis.com feed, 2026-07-11). Version-pinned only:
  `jscrambler` is a legitimate package, so the bare name is intentionally NOT
  blocked - only the exact compromised version matches.

## [5.12.0] - 2026-07-11
**Issue #54 hardening: oversized-file transparency + threat-intel indicator contract**

Implements both hardening gaps tracked in issue #54 (follow-up to the merged
PR #55 extraction/IOC hardening), plus the dependency maintenance merged this
cycle (docker/login-action 4.4.0, vitest + @vitest/coverage-v8 4.1.10). This
minor also carries PR #55's archive-extraction and self-scan-suppression fix
to npm (it landed after v5.11.1 was published).

- New rule `FILE_TOO_LARGE_SKIPPED` (info): the core, VSIX, npm, and PyPI
  scanners no longer skip files above the 5 MB content-scan limit silently -
  every skipped scannable file is surfaced with its path and size, because an
  attacker can deliberately pad a payload past the limit to dodge scanning.
  info severity: never affects exit codes; filterable via --min-severity or
  --exclude FILE_TOO_LARGE_SKIPPED. The oversized body is never read.
- Threat-intel indicator contract: feed values are LITERAL indicators, never
  regexes. Domain values were previously compiled to RegExp with only dots
  escaped, so a hostile or malformed remote feed value like "(" threw inside
  the per-file loop - swallowed by the per-file catch, silently disabling all
  downstream checks for every file while the scan exited green, and a valid
  catastrophic pattern ("(a+)+b") would be ReDoS-tested against full file
  contents. Now: full metacharacter escaping (values match only themselves),
  compiled once per unique value, with a substring fallback that can never
  throw.
- Type-aware quarantine at every feed ingestion point (`feed refresh`, the
  legacy update API, and the cached-feed load at scan time): each entry must
  match its type's shape (domain/ip/url/hash/package charsets, 2048-char cap).
  Invalid entries are dropped deterministically; a rejected refresh never
  overwrites the previous cache. This also stops a structurally-valid garbage
  literal like a bare "(" from flooding reports with false matches.
- npm/PyPI extracted-file walkers are now exported (scanExtractedNpmFiles /
  scanExtractedFiles) so the size-limit behavior is regression-tested without
  network; 16 new tests across all five scanner families and all three
  ingestion paths.
- An adversarial review gate BLOCKED the first candidate with 6 confirmed
  findings, all fixed pre-tag: (1)+(2) the ip/url value shapes were
  charset-only, so a degenerate flood value like ip "." or url "(" passed the
  quarantine and substring-matched a critical finding onto virtually every
  scanned file - ip now requires IPv4/IPv6 structure, url an 8-char floor;
  (3) the domain regex cache was unbounded (long-running MCP server + rotating
  hostile feed = monotonic memory growth) - now cleared at 10k entries;
  (4) severity is enum-checked and confidence range-checked (an unknown
  severity string would have produced NaN scores downstream); (5) the
  skills-scanner's agent-rules reader also surfaces oversized files now
  (fifth family, full DoD parity); (6) the feed-reject error message bounds
  the attacker-controlled type field, not just the value.

## [5.11.1] - 2026-07-09
**CI: fix the npm-publish job (npm 12 dropped Node 20 support)**

The v5.11.0 tag built and tested green but its publish job failed at "Upgrade
npm for OIDC trusted publishing": `npm install -g npm@latest` now resolves to
npm 12.0.0, which requires Node >=22 and hard-fails EBADENGINE on the Node 20
publish runner. So v5.11.0 never reached npm (GitHub Release and the `v5`
branch fast-forward were skipped with it).

- Pinned the OIDC npm upgrade to `npm@11` (OIDC-capable since 11.5.1 AND
  Node-20-compatible) instead of the floating `npm@latest`.
- This is a no-code-change infra patch: it carries the full v5.11.0 payload
  (fake Paysafe / Skrill / Neteller SDK IOCs + the new MALICIOUS_DEPENDENCY
  directory-scan rule) to npm, since v5.11.0 could not publish.

## [5.11.0] - 2026-07-09
**Threat intel: fake Paysafe / Skrill / Neteller payment SDKs (npm + PyPI)**

Adds indicators for a coordinated typosquat campaign reported by Socket on
July 8, 2026. 17 packages published ~July 7 impersonate non-existent official
payment SDKs: they expose the expected APIs but return fake success responses
and exfiltrate every environment variable matching KEY/SECRET/TOKEN/PASS/AUTH/
API (Paysafe and AWS keys, GitHub and npm tokens) via HTTPS POST to an ngrok
tunnel.

- 13 npm packages (versions 1.0.0-1.0.3): paysafe-checkout, paysafe-vault,
  paysafe-js, paysafe-api, paysafe-node, paysafe-cards, paysafe-fraud,
  paysafe-kyc, paysafe-payments, skrill, skrill-sdk, skrill-payments, neteller.
- 4 PyPI packages (1.0.0): paysafe-kyc, paysafe-payments, paysafe-sdk,
  paysafe-api. All names were added to MALICIOUS_PACKAGE_PATTERNS /
  PYPI_TYPOSQUAT_PATTERNS (anchored, exact-name); the 13 observed npm names plus
  the C2 also populate the bundled threat-intel feed (the PyPI-only paysafe-sdk is
  pattern-covered, not added to the npm-scoped feed).
- C2: the exact exfil tunnel caliber-spinner-finishing[.]ngrok-free[.]dev
  (:443) added to the known-C2-domain blocklist (a specific subdomain, not a
  broad ngrok-free[.]dev block, so no false positives on legitimate tunnels).
- New: a directory scan now flags dependency names in package.json that are
  exact known-malicious feed IOCs (rule MALICIOUS_DEPENDENCY), so scanning your
  own repo catches a bad dependency - previously only the `npm <pkg>` and
  install-guard paths did. Matches exact feed IOCs, not the broad typosquat
  heuristics, so legitimate scoped deps are not false-flagged.

## [5.10.0] - 2026-07-08
**GitLost-class agentic-workflow posture detection**

Closes the gap surfaced by Noma Security's "GitLost" disclosure (July 2026): an
AI agent driven by a GitHub workflow can be prompt-injected through an untrusted
issue/PR into leaking private-repo data via a public comment. The runtime attack
is GitHub's to fix; what is static and checked-in is the vulnerable POSTURE, and
that is now scannable before an attacker files the issue.

- **`GHA_AGENT_UNTRUSTED_PROMPT`** (critical): an AI-agent step (claude-code-action,
  gh-aw, gemini/codex CLIs, ...) interpolates attacker-controllable event context
  (issue/PR/comment body or title) into its prompt on an untrusted trigger.
- **`GHA_AGENT_PUBLIC_POST`** (high): the agent job also holds issues:write /
  pull-requests:write - the public-comment exfiltration channel.
- **`GHA_AGENT_CROSS_REPO_TOKEN`** (high): a non-default token secret is fed to the
  agent (the cross-repo read that widens a single-repo injection to an org-wide leak).
- **`GHA_AGENT_NO_AUTHOR_GATE`** (medium): an issue/comment-triggered agent with no
  author-trust gate - the anonymous entry point GitLost used.
- **New `agentic-workflow-scanner.ts`**: scans GitHub Agentic Workflow markdown
  (`.github/workflows/*.md`, the gh-aw format the .yml-only scanner skipped) for
  `AGENTIC_WF_UNTRUSTED_TRIGGER`, `AGENTIC_WF_PUBLIC_POST_TOOL`, `AGENTIC_WF_BROAD_ACCESS`,
  and LLM control tokens in the instruction body (`AGENTIC_WF_PROMPT_INJECTION`). The
  compiled `*.lock.yml` companion is already covered by the YAML scanner's new rules.
- **Correlation incident** "GitLost-class Agentic Workflow Exfiltration Posture"
  (any 2 signals, requires at least one strong ingest/post signal) plus a scoring fix:
  `AGENTIC_WF_` / `SKILL_` / `MCP_` findings now count toward the CI/CD risk dimension
  (previously they contributed to no dimension).
- **AST robustness**: `workflow-ast.ts` now captures agent-step prompt/token/env fields
  and parses the compact `on: { ... }` flow-map trigger form.
- **Class-level hardening** (not a GitLost detector, but the same attack class): the
  prompt-injection patterns now cover `.github/ISSUE_TEMPLATE/*` and `PULL_REQUEST_TEMPLATE`,
  and the invisible-Unicode detection now catches Unicode Tags (U+E0000..U+E007F) ASCII
  smuggling in agent-readable files.
- No IOC feed changes: GitLost has no attacker infrastructure (the disclosure PoC
  repos are researcher infra and are intentionally NOT blocklisted).

## [5.9.0] - 2026-07-07
**Opt-in registry version-drift detection (`--check-registry`)**

Implements the future-work item deferred in v5.8.0. A new opt-in check compares the
local `package.json` version against the npm registry `latest` dist-tag and flags when
the source you are auditing is a major version behind what `npm install` actually
delivers (e.g. TencentDB-Agent-Memory source `0.3.6` vs npm `latest 1.0.0`).

- **`REGISTRY_VERSION_DRIFT_MAJOR`** (medium): source is one or more majors behind the
  published `latest`. Signals that the published artifact may not correspond to the
  audited source - an unauthorized publish, or review against the wrong revision.
- **Opt-in and offline-safe**: enabled only with `scan --check-registry`. Without the
  flag no network call is made, so the offline default is preserved. The fetch resolves
  to null on any error/timeout/non-200 (never throws), and a same-major minor/patch lag
  or a source-ahead dev build is intentionally not flagged (both are benign and common).
- Lives in `publishing-anomaly-detector.ts` (`evaluateVersionDrift` pure logic +
  injectable `fetchNpmLatest` + `checkRegistryVersionDrift`); 10 new tests, none of which
  touch the network. Verified live against the npm registry.

## [5.8.0] - 2026-07-07
**Agent host-runtime patch detection + OpenClaw plugin posture**

- **`INSTALL_HOOK_HOST_RUNTIME_PATCH`** (high): npm install hooks that patch or
  mutate a host agent runtime (OpenClaw, Hermes, Claude Code) during installation -
  rewriting another installed package's code to hook into it (e.g. intercept
  after-tool-call messages). Modelled on the TencentDB-Agent-Memory postinstall
  (`bash scripts/openclaw-after-tool-call-messages.patch.sh 2>/dev/null || true`),
  which patches the OpenClaw runtime's dispatch/hook files at install time. Fires
  only on a host-runtime target combined with a code-mutation action, so ordinary
  build hooks (`node scripts/build.js`, `npm run build`, `tsc`, `patch-package`)
  do not match.
- **OpenClaw plugin manifest posture** (new `openclaw-plugin-scanner.ts`, reads
  `openclaw.plugin.json`): informational/medium context for agent-memory plugins -
  `OPENCLAW_PLUGIN_STARTUP_ACTIVATION`, `OPENCLAW_PLUGIN_AUTOCAPTURE` (medium),
  `OPENCLAW_PLUGIN_EXTERNAL_LLM` (medium), `OPENCLAW_PLUGIN_CLOUD_BACKEND`,
  `OPENCLAW_PLUGIN_TELEMETRY`. Only fires when the manifest is present, so no noise
  on ordinary packages.
- **Future work**: registry version-drift detection (source `package.json` version
  vs npm `latest` dist-tag, e.g. the TencentDB 0.3.6-on-GitHub vs 1.0.0-on-npm gap).
  This needs npm registry metadata that local/offline directory scans currently
  avoid; proposed here, not yet implemented.

## [5.7.0] - 2026-07-07
**GitHub Actions: Cordyceps cross-workflow composition detection**

Closes the gap identified in novee.security's "Cordyceps" research (BleepingComputer,
July 2026): CI scanners that pattern-match one workflow file at a time stay green on
attacks that live in how workflows COMPOSE, because no single line is wrong. This release
makes the GitHub Actions analysis trigger-aware and adds a cross-file trust-boundary pass.

- **New `workflow-ast.ts`**: a zero-dependency structural parser that finally lets the
  scanner see a workflow's `on:` triggers, top-level and per-job `permissions:`, and each
  step's `uses` / `run` / `with` (ref, script, artifact name). No YAML dependency was
  added: a supply-chain tool should not grow its own supply-chain surface.
- **New `workflow-graph.ts` + `GHA_CROSS_WORKFLOW_ARTIFACT_TRUST`** (the core detection):
  models the producer to consumer graph across ALL workflow files and flags a privileged
  `workflow_run` consumer that downloads (critical if it then executes) an artifact
  produced by an untrusted PR-triggered workflow. This is the composition attack
  single-file scanners miss.
- **New trigger-aware single-file rules** in `github-actions-scanner.ts`:
  - `GHA_PRIVILEGED_TRIGGER`: workflow runs in the base-repo context with secrets and a
    write token (`pull_request_target`, `workflow_run`, `issue_comment`, ...).
  - `GHA_PWN_REQUEST_CHECKOUT` (critical): privileged trigger that checks out PR/head code
    and then runs it (the canonical "pwn request").
  - `GHA_GITHUB_SCRIPT_INJECTION`: untrusted event context eval'd as JavaScript inside an
    `actions/github-script` block.
  - `GHA_PERMS_WRITE_ALL` / `GHA_PERMS_DEFAULT_BROAD`: overly broad or unscoped
    `GITHUB_TOKEN` permissions, the loot a compromised workflow hands over.
- **Broadened `GHA_SCRIPT_INJECTION`**: now also covers `github.event.comment.body` (the
  `issue_comment` vector), `review.body`, `discussion.*`, and PR head ref/label: fields the
  pre-v5.7 regex missed entirely.
- **Correlation**: new "Cordyceps CI/CD Composition Attack" incident compounds any two of
  the above single-file symptoms into one critical, high-confidence incident.
- **Note**: this campaign publishes no IOCs (it is a composition pattern, not a malware
  family), so nothing is added to the threat-intel/IOC feed: the work is detection logic.
- **Hardened by an adversarial review gate** that BLOCKED the first candidate with 14
  confirmed findings, all fixed pre-release: a correlation false-CRITICAL on ordinary
  pull_request_target bots (now gated on a strong signal), plus valid-YAML evasions of the
  new critical rules - bare-dash steps, `refs/pull/N` and matrix/step-output checkout refs,
  `gh run download` consumers, quoted `"on":` keys, and misindented comments. Self-scan
  0 findings, 46 new tests.

## [5.6.3] - 2026-07-07
**Threat intel: PolinRider DPRK open-source supply-chain campaign**

Daily threat-intel refresh. Added indicators for the PolinRider campaign (2 new indicators):

- **PolinRider** (North Korea / Contagious Interview / Famous Chollima; Socket, The Hacker News,
  SecurityWeek, 2026-07-06): a DPRK-linked cluster, active since December 2025, that poisoned 108
  packages and extensions (162 release artifacts) across npm, Packagist, Go modules and Chrome to
  deliver the DEV#POPPER RAT and the OmniStealer infostealer. Obfuscated JavaScript loaders hidden
  in `config.js` files and fake `.woff2` fonts run via VS Code tasks on folder-open, decrypt a
  second stage fetched over TRON / Aptos / BNB Smart Chain RPC using an embedded XOR key, and
  `eval()` it. Only the concretely enumerated malicious Go module is pinned - `git2md` from the
  compromised GitHub account `Xpos587` (`github[.]com/Xpos587/git2md`) - plus that account in the
  GitHub-account blocklist. The npm/Composer package names and the Chrome extension ID were not
  publicly enumerated at feed time, and the legitimate `7span`/`sevenspan` and `Artiffusion-Inc`
  accounts are deliberately not blocked to avoid false positives on their non-weaponized repos.

## [5.6.2] - 2026-07-04
**Threat intel: Contagious Interview Rollup-polyfill npm wave + ChocoPoC RAT**

Daily threat-intel refresh. Two new July 2026 developer-targeted campaigns added
to the bundled IOC feed and detection patterns (12 new indicators):

- **Contagious Interview Rollup Polyfill** (Lazarus / DPRK, JFrog via THN, 2026-07-03):
  6 attacker-uploaded npm packages masquerading as Rollup polyfill tooling to
  facilitate remote access and developer-secret theft (rollup-packages-polyfill-core,
  rollup-runtime-polyfill-core, rollup-plugin-polyfill-connect, quirky-token,
  react-icon-svgs, swift-parse-stream) plus C2 IP 216.126.236[.]244 (same 216.126.x
  range as the OtterCookie / Megalodon DPRK infrastructure). JSONKeeper, the legit
  paste service abused as a dead-drop, is deliberately not blocked (false positives).
- **ChocoPoC Fake PoC Repos** (THN, 2026-07-02): a data-stealing trojan hidden in
  fake Python PoC exploit repos on GitHub that target vulnerability researchers.
  Malicious PyPI packages skytext / frint (plus the same actor's late-2025 slogsec /
  logcrypt.cryptography) and upload-server IP 91.132.163[.]78. Mapbox, abused as a
  DoH dead drop, is deliberately not blocked.
- feed.json regenerated; 4 new campaign tests (1122 total, unchanged suite pass rate).

## [5.6.1] - 2026-07-03
**Polish: Docker base LTS, GitLab report path privacy, docs**

- Docker base image bumped to node:22-alpine (digest-pinned); dependabot now
  brings only digest/patch/minor node refreshes, not major jumps. Declined
  dependabot #49 (node 20 -> 26-alpine): 26 is premature as the base for a
  security tool's own published image.
- `--format gitlab`: `location.dependency.package.name` now uses the per-finding
  file instead of the scan target, so an absolute runner path is no longer
  leaked into a shared GitLab Dependency Scanning report.
- Docs: Jenkins example notes how to pin the scanner version for reproducible
  CI; the Install Guard README documents that offline checks only resolve exact
  version pins (bare-name IOCs still fire on any version).

## [5.6.0] - 2026-07-03
**Install-time guard + GitLab-native output + registry hardening (both remaining roadmap bets)**

Ships the last two strategic bets from the 2026-07 roadmap. A second 4-lens
adversarial verification gate reviewed the diff and BLOCKED the first candidate
with 5 confirmed findings, all fixed here (a real Windows RCE among them).
40 new tests (1120 total).

- **Install Guard** (Bet 2): `supply-chain-guard guard <npm|pnpm|yarn|bun>
  [args...]` checks each package spec against the offline IOC feed +
  known-bad-version blocklist + typosquat heuristics BEFORE the package manager
  runs any lifecycle script; a hit blocks the install (exit 2). `--force`
  overrides with a loud warning, `--dry-run` never invokes the manager. The
  only install blocker whose entire blocklist is auditable in git history,
  offline, no account.
- **GitLab-native output** (Bet 3, delivered on the v5.5.0 GHCR image):
  `--format gitlab` emits a GitLab Dependency Scanning report (schema 15.2.4)
  for artifacts:reports:dependency_scanning, so findings surface in the GitLab
  security UI. Suppressed findings are excluded (mirrors the SARIF path).
- **Registry hardening**: the Open VSX download and every redirect hop are now
  constrained to an https host allowlist (open-vsx.org + its storage host);
  the /tmp -> os.tmpdir() migration is finished across npm/pypi scanners.
- **CI/infra**: Docker base images pinned by sha256 digest (with a weekly
  dependabot docker ecosystem to refresh them); the Jenkins example uses npx;
  `scan --no-history` skips writing .scg-history/ (the pre-commit hook uses it
  so hooks never write state into consumer repos).

Fixed by the verification gate before release:
- **Windows command injection (critical)** in the Install Guard: the cmd.exe
  argument escaping was single-pass, but the npm/pnpm/yarn/bun .cmd shims
  re-parse %*, so a crafted package token (`x"&echo ...&"`) could execute
  arbitrary commands. Now double-escaped (cross-spawn doubleEscapeMetaChars),
  proven closed by the gate's own PoC.
- Install-verb bypasses: `npm isntall` (and the other documented typo-aliases),
  `yarn global add`, and a value-taking global flag before the verb
  (`npm --prefix x install evil`) all silently skipped scanning. Verb detection
  rewritten; flag values are no longer misread as package specs.
- `--format gitlab` could emit a >255-char vulnerability name that fails the
  GitLab schema, making GitLab discard the whole report; names are now capped.

## [5.5.0] - 2026-07-02
**Community batch: all 8 seeded issues shipped, hardened by an adversarial release gate**

Implements every open issue (#40-#47) in one release. Before tagging, a
4-lens adversarial verification gate reviewed the full diff and BLOCKED the
first candidate with 6 confirmed findings - all fixed here (details below).
35 new tests (1057 total).

- **Open VSX registry support** (#40): `supply-chain-guard vscode <id>
  --registry openvsx` scans extensions from open-vsx.org (VSCodium, Gitpod,
  Theia); marketplace stays the default. Windows fix: scanner temp dirs now
  use os.tmpdir() instead of /tmp.
- **Badge output** (#42): `--format badge` emits Shields.io endpoint JSON.
  The badge derives from the findings summary, mirroring exit-code semantics
  (critical = red, high = orange, medium = yellow, else green).
- **pre-commit hook** (#41): .pre-commit-hooks.yaml + a "prepare" build script
  so git-based installs compile dist/; README documents the
  .pre-commit-config.yaml snippet.
- **CI recipes** (#44, #45, #46): examples/ gains CircleCI, Jenkins, and Azure
  Pipelines gate configs.
- **Official Docker image** (#47): multi-stage Dockerfile (non-root, unzip
  included, installs the locally built tarball of the tagged source) +
  docker.yml publishing multi-arch (amd64/arm64) images to
  ghcr.io/homeofe/supply-chain-guard on every release tag, with provenance and
  SBOM attestations. All workflow actions SHA-pinned and verified upstream.
- **Coverage gate** (#43): vitest v8 coverage with thresholds wired into CI;
  coverage summary uploaded as a build artifact.

Fixed by the verification gate before release (would have shipped broken):
- Docker build died at `npm ci` (the new prepare script ran before
  tsconfig/src existed in the layer) - now --ignore-scripts in the builder.
- Badge severity inversion: one critical finding scored "medium" risk level
  and rendered a YELLOW badge while the CLI exited 2 - badges now mirror the
  gate.
- `prepare: npx tsc` could download and execute the namesquatted "tsc"
  registry package on cold installs - now plain `tsc` (bin-PATH only).
- pre-commit docs pinned rev v5.4.2, a tag that predates the hook file - now
  gate-enforced via check:version-sync.
- CircleCI example used an invalid `when:` key and would not compile.
- The README badge recipe froze the badge green exactly when findings
  appeared (scan exits non-zero, publish step skipped) - now || true +
  if: always().

## [5.4.2] - 2026-07-02
**Fix: policy-suppressed findings leaked into incidents and the trend check**

Found by a real user scan of this repository: the report said "No findings -
clean" while simultaneously showing a "[CRITICAL] Shai-Hulud npm Worm, 100%
confidence" incident, and the second scan of any repo with suppressions raised
a phantom RISK_TREND_SPIKE ("spiked from 8 to 51"). Same bug class as the
v5.2.40 SARIF/SBOM suppressed-finding leaks.

- Policy suppression now runs BEFORE the downstream analytics: the correlation
  engine, trust breakdown, risk trend, forecast, and triage governance all
  operate on the post-suppression finding set. Suppressed findings can no
  longer produce incident boxes, correlation risk boosts, or phantom trend
  spikes.
- A second policy pass covers the late-generated findings, so rules like
  RISK_TREND_SPIKE remain suppressible via .supply-chain-guard.yml.
- Side effect: this repo's own self-scan now reports an honest 0/100 CLEAN -
  the previous constant 8/100 was itself leak residue (correlation risk boost
  computed from the two documented doc-generator suppressions).
- 5 regression tests (bugfix-v5_4_2.test.ts) covering the incident leak, the
  score-boost leak, the phantom spike, and trend-rule suppressibility.

## [5.4.1] - 2026-07-02
**Docs: PowerShell-safe MCP install instructions**

Patch release so the npm package page carries the corrected instructions.

- The documented MCP one-liner (`claude mcp add ... -- npx -y ...`) fails in
  PowerShell, which consumes the bare `--` before the claude CLI sees it
  (`error: unknown option '-y'`). README and docs/mcp.md now lead with the
  shell-agnostic form that also avoids npx cold-start connect timeouts:
  `npm install -g supply-chain-guard` + `claude mcp add supply-chain-guard
  supply-chain-guard mcp`. The npx one-liner remains documented for bash/zsh.
- Repo hygiene: the `.scg-cache/` runtime feed cache is untracked and
  gitignored (a live `feed refresh` test had briefly committed it).

## [5.4.0] - 2026-07-02
**The agentic security suite: MCP scanning, skills scanning, an MCP server, and a live threat feed**

supply-chain-guard becomes both a scanner OF the agentic ecosystem and a tool FOR it.
No mainstream OSS scanner covers these surfaces. 106 new tests (1030 total).

- **MCP server config scanner** (mcp-scanner, 6 MCP_ rules): scans .mcp.json,
  .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json and
  .gemini/settings.json for malicious server packages (matched against the bundled
  IOC feed and known-bad versions), C2 endpoints, plain-http servers, credentials
  forwarded to remote servers, prompt injection inside tool descriptions, and
  unpinned npx -y servers.
- **AI agent skills / rules-file scanner** (skills-scanner, 5 SKILL_/AGENT_ rules):
  scans .claude/skills/**/SKILL.md, .claude/commands, .claude/settings.json hooks,
  .cursorrules, .cursor/rules, .github/copilot-instructions.md, AGENTS.md and
  CLAUDE.md for injected LLM control tokens, invisible-Unicode instruction channels,
  download-and-execute and credential-harvesting instructions, and dangerous hook
  commands. Tuned against false positives: legitimate rules files (including this
  repo's own) produce zero findings.
- **Built-in MCP server** (`supply-chain-guard mcp`): zero-dependency JSON-RPC 2.0
  server over stdio exposing ioc_lookup (offline, all 5 package ecosystems),
  scan_directory, and scan_npm_package - so AI coding agents can vet packages
  BEFORE installing them. Client snippets for Claude Code, Claude Desktop, and
  Cursor in docs/mcp.md.
- **Live threat feed**: the bundled IOC feed is now published as feed.json (kept
  release-fresh by a new check:feed prebuild gate) and `supply-chain-guard feed
  refresh` pulls it into the local cache, where every scan merges it for 24h -
  same-day protection between releases. `feed stats` shows the effective feed.
- Scanner hygiene: the published feed and its cache are recognized as inert,
  strictly schema-validated detection data (a repo committing feed.json no longer
  drowns in phantom criticals from its own protection data); .scg-cache/ and
  .scg-history/ excluded from walks.

## [5.3.0] - 2026-07-02
**Ecosystem expansion: 3 new ecosystems, 4 new lockfile formats, fail-closed policy config**

The largest coverage release since v5.0: three new package ecosystems, full modern
JavaScript lockfile coverage, strict policy validation, and community infrastructure.
94 new tests (917 total).

- **pnpm / yarn / bun lockfile support**: `checkLockfile` now parses pnpm-lock.yaml
  (v6 + v9 key styles), yarn.lock (classic v1 AND Berry v2+), and bun.lock (JSONC),
  applying the same integrity, registry-URL, git/tarball-dependency, and known-bad-
  version checks as package-lock.json. Binary bun.lockb files are flagged
  (LOCKFILE_BUN_BINARY_UNAUDITABLE) with a migration hint. All hand-rolled parsers,
  zero new dependencies.
- **RubyGems, Composer, and NuGet scanners**: new rubygems-scanner, composer-scanner,
  and nuget-scanner modules parse Gemfile/Gemfile.lock, composer.json/composer.lock,
  and packages.lock.json/*.csproj/nuget.config. This activates the ruby:/composer:/
  nuget: package IOCs already bundled in the threat-intel feed (previously dead
  weight: BufferZoneCorp sleeper gems, Laravel-Lang DebugElevator, Sicoob.Sdk and
  friends now fire). 10 new rules across RUBY_/COMPOSER_/NUGET_ categories, plus
  hygiene checks for plain-http gem sources, dist URLs, and package feeds.
- **Fail-closed policy validation**: .supply-chain-guard.yml is now strictly
  validated. Unknown sections or keys (e.g. a typo like "supress:") raise
  POLICY_UNKNOWN_KEY (high) instead of being silently ignored - a misspelled policy
  no longer fails open. Suppressions without a reason raise
  POLICY_SUPPRESSION_NO_REASON; malformed rule ids raise POLICY_MALFORMED_RULE_ID.
  Ships policy-schema.json (JSON Schema) in the npm package for editor validation
  via yaml-language-server.
- **Community infrastructure**: .devcontainer (all 930 tests green in-container,
  including the 13 zip-dependent ones), examples/ directory (GitHub Action basic,
  Renovate/Dependabot bot-PR gate, GitLab CI), CONTRIBUTING refresh, new-pattern
  label, and 8 seeded good-first-issues (#40-#47).

## [5.2.45] - 2026-07-02
**README adoption package: demo GIF, comparison table, changelog split**

Documentation and discoverability release. No detection-logic changes.

- Animated demo GIF at the top of the README (rendered by VHS in CI from
  assets/demo.tape, scanning the malicious test fixture: risk gauges, GlassWorm
  incident correlation, remediation plan).
- New "How It Compares" README section: fact-checked, honest comparison with
  OSV-Scanner, Socket, GuardDog, OpenSSF Scorecard, and npm audit, plus
  "pairs well with" CI recipes. Positioning: supply-chain-guard is the
  malware / behavior / campaign-IOC layer; pair it with a CVE scanner.
- Changelog moved out of the README into this CHANGELOG.md (README went from
  90KB to ~23KB) with a table of contents; the check:changelog prebuild gate
  and the CI release-notes extraction now read CHANGELOG.md.
- Discoverability: GitHub repo description and topics refreshed (9 -> 19
  topics), npm keywords extended, package description synced to the current
  170+ indicator claim.
- Self-scan hygiene: two documented Shai-Hulud suppressions for this repo's
  own doc-generator script (its templates mention the npm publish pipeline);
  detection unchanged for scanned projects. The demo render workflow installs
  vhs from the Charm apt repo, so the repo is back to zero third-party
  GitHub Actions.

## [5.2.44] - 2026-07-01
**Dependency maintenance: latest toolchain + commander 14**

Routine dependency refresh. All dependencies are now at their latest versions with zero known
vulnerabilities. No detection-logic or output-format changes: this is a maintenance-only release.

- Runtime: commander 13 -> 14 (stays on the CommonJS line; commander 15 is ESM-only and requires
  Node >=22.12, incompatible with this CommonJS package on Node >=20).
- Dev/build: typescript 5 -> 6 (added an explicit `"types": ["node"]` to tsconfig.json, since
  TypeScript 6 no longer auto-includes @types/node), vitest 3 -> 4, @types/node 22 -> 26, and the
  test runner's transitive vite 7 -> 8 plus an esbuild refresh. Removed two now-obsolete
  esbuild/vite overrides.
- CI: pinned GitHub Actions bumped to current releases (checkout v7, setup-node v6, github-script
  v9, setup-python v6); SHA pins verified against the upstream tags.

## [5.2.43] - 2026-06-30
**Threat intel: Contagious Interview "Fake Font" npm + Go wave (June 29, 2026)**

Adds indicators for a DPRK Contagious Interview operation reported by The Hacker News on
June 29, 2026. Two attacker-uploaded npm packages and a cluster of 16 Go modules hide a
JavaScript payload disguised as a web font (`public/fonts/fa-solid-400.woff2`) plus a
hidden VS Code task (`eslint-check`) that deploys the InvisibleFerret Python backdoor.
TronGrid and Aptos blockchain transactions act as the dead-drop resolver; harvested data
is exfiltrated as ZIP archives to a C2 server or a runtime-supplied Telegram bot.

- npm package names `html-to-gutenberg` and `fetch-page-assets` (uploaded 2026-05-25, since
  removed) added to `MALICIOUS_PACKAGE_PATTERNS` as bare-name indicators.
- 16 malicious Go module paths (e.g. `github.com/lambda-platform/lambda`,
  `github.com/reauheau/goaubio`, `github.com/dexbotsdev/uniswap-v2-v3-arbitrage`) added as a
  `MALICIOUS_PACKAGE_PATTERNS` alternation and recorded in the bundled threat-intel feed.
- 18 new bundled-feed IOC entries and a `campaigns.test.ts` regression suite, including a
  guard that the disguised FontAwesome filename is deliberately NOT used as a signature.
- No file hashes, C2 domains, IPs, or wallet addresses were disclosed in the report.

## [5.2.42] - 2026-06-29
**Threat intel: Miasma LeoPlatform / GitHub Actions wave (June 26, 2026)**

Adds indicators for the latest evolution of the Mini Shai-Hulud / Miasma / Hades npm
worm family, reported by The Hacker News on June 26, 2026. A compromised LeoPlatform npm
maintainer account (`czirker`) republished the LeoPlatform / RStreams SDK packages plus
`hexo-*` plugins with a preinstall credential stealer; the worm also propagated to the Go
ecosystem and abused the `codfish/semantic-release-action` GitHub Action.

- 23 compromised npm package@version pairs pinned in `KNOWN_BAD_NPM_VERSIONS` (clean
  upstream versions stay legitimate): `leo-sdk@6.0.19`, `leo-streams@2.0.1`, `leo-auth@4.0.6`,
  `leo-aws@2.0.4`, the `leo-connector-*` set, `rstreams-metrics@2.0.2`,
  `rstreams-shard-util@1.0.1`, `serverless-leo@3.0.14`, `serverless-convention@2.0.4`,
  `prism-silq@1.0.1`, `solo-nav@1.0.1`, `hexo-deployer-wrangler@1.0.4`, and others.
- Go module `github.com/verana-labs/verana-blockchain@v0.10.1-dev.20` recorded in the
  bundled threat-intel feed.
- New campaign signature `MIASMA_LEO_REVOKE_KABOOM` for the `RevokeAndItGoesKaboom`
  token-relay marker.
- Compromised maintainer handle `czirker` added to the malicious-account blocklist.
- 24 new bundled-feed IOC entries and a `campaigns.test.ts` regression suite.

## [5.2.41] - 2026-06-28
**Security: command injection in the GitHub trust scanner**

Remediates a finding from the continuous AAHP Swarm review (elvatis/ideabase#24).
`github-trust-scanner.ts` built five `gh api repos/${owner}/${repo}` calls as shell
strings via `execSync`, with `owner` and `repo` unvalidated. Because
`analyzeGitHubTrust` and `parseGitHubUrl` are public API, a consumer passing crafted
values could reach shell command execution. No rule or scan-engine change.

- Every `gh api` call now uses `execFileSync` (no shell).
- `analyzeGitHubTrust` validates owner and repo against GitHub-name allowlists (owner
  cannot begin with a hyphen; repo forbids `..`) before any call, and `parseGitHubUrl`
  rejects values that fail the same allowlists.
- Added regression tests.

## [5.2.40] - 2026-06-28
**Security: org-scanner command injection and suppressed findings in SARIF/SBOM**

Remediates findings from the continuous AAHP Swarm review (elvatis/ideabase#24).
No rule or scan-engine behavior changed.

- `org-scanner.ts`: `listOrgRepos` built `gh repo list ${org}` and ran it through a
  shell with the `org` CLI argument unvalidated (command injection, the same class
  as the v5.2.38 clone fix, in a sibling path). It now uses `execFileSync` with an
  org-name allowlist that also forbids a leading hyphen (no gh flag injection).
- `reporter.ts`: SARIF results and the fallback SBOM emitted policy-suppressed
  findings as active results. Both now filter out `suppressed` findings, matching
  the primary SBOM path.
- Added regression tests for the rejected-org path and suppressed-finding output.

## [5.2.39] - 2026-06-28
**Security: harden the GitHub Action and PR-comment report against injection**

Remediates findings from an internal AAHP Swarm review of this tool. The composite
Action interpolated workflow inputs straight into a bash run block (script
injection) and used an unquoted argument string; the markdown report embedded
attacker-controlled scan content (finding match, rule, file, description, target,
and recommendations) into code spans and headers without escaping, allowing
markdown and HTML injection into the PR comment the Action posts. No rule or
scan-engine behavior changed.

- `action.yml` passes inputs via `env:` and builds a quoted bash array, so a
  crafted input can no longer reach the shell as code; the report file uses
  `RUNNER_TEMP` and a random `GITHUB_OUTPUT` delimiter.
- `reporter.ts` escapes every attacker-controlled value in the markdown report
  (new `mdInlineCode`, `mdText`, and table-cell `mdCell` helpers).
- `scanner.ts` uses `os.tmpdir()` instead of a hardcoded `/tmp` for the clone.
- Added a markdown-injection regression test.

## [5.2.38] - 2026-06-28
**Security: command injection in GitHub clone and diff scanning**

The GitHub clone path and the diff scanner ran git through a shell with the target
URL and the `--since` ref interpolated into the command string, guarded only by a
`startsWith` prefix check. A crafted value could break out of the quoting and run
arbitrary shell commands on the host running the scan. Both now invoke git via
`execFileSync` (no shell) with strict input validation, and the git-log anomaly
check moved off the shell too. Found by an internal AAHP Swarm review.

- `scanner.ts` clones via `execFileSync` plus a strict GitHub-URL allowlist for
  the clone target.
- `diff-scanner.ts` runs `git diff` and `ls-files` via `execFileSync` and rejects
  a `sinceCommit` that is not a clean git ref.
- Added a regression test for the rejected-ref path.

## [5.2.37] - 2026-06-27
**Fix: PR-comment step crash on findings containing backticks**

The Comment on PR step built a JavaScript template literal from the scan
report. Because the report markdown contains backticks, the literal broke and
the step threw, failing the check on essentially every consumer pull request
(the scan logic itself was never affected). The step now reads the report from
a file via `fs.readFileSync` and is marked `continue-on-error`, so a comment
failure can never fail the scan. No rule, threat-intel, or scan-engine changes
in this release.

- Composite action `Comment on PR` step rewritten to read `/tmp/scg-report.txt`
  instead of interpolating the report into an inline template literal (#27).
- Added `continue-on-error: true` so PR-comment failures are non-fatal.

## [5.2.36] - 2026-06-25
**Threat-intel update: PostCSS Tools Windows RAT npm campaign**

One confirmed campaign ingested from the daily threat-intel sweep (source: The Hacker News, June 23, 2026):

- **PostCSS Tools Windows RAT (June 23, 2026)**: malicious npm packages posing as PostCSS tooling deliver a Windows-based remote access trojan. The two confirmed, fully malicious packages are `aes-decode-runner-pro` (145 downloads) and `postcss-min`. The feed excerpt disclosed no C2 infrastructure, file hashes, or publisher account, so the bare package names are the only extractable indicators. Added to `MALICIOUS_PACKAGE_PATTERNS` (bare-name) and `BUNDLED_FEED` (confidence 0.9), with a new `campaigns.test.ts` describe block covering both names.

Deliberately not ingested this sweep: the Operation Endgame Amadey/StealC takedown, the Cisco SD-WAN (CVE-2026-20245) and Ubiquiti/Lantronix CVEs, Edgecution, Mistic RAT, and FortiBleed - none are package-ecosystem compromises with extractable, version-pinned or named-package IOCs.

## [5.2.35] - 2026-06-21
**Security: fix vite devDependency vulnerabilities**

Two new advisories in the transitive vite dependency (via vitest), both `devDependencies` that do not ship in the published npm tarball (`files[]` is `dist`, `action.yml`, `README.md`, `LICENSE`, `socket.yml`), so package consumers were never exposed.

- **vite** forced from 7.3.2 to `^7.3.5` via the existing `overrides` block, resolving GHSA-fx2h-pf6j-xcff (high) and GHSA-v6wh-96g9-6wx3 (medium). Patch-level bump within 7.x; all 803 tests pass unchanged.
- `npm audit` reports 0 vulnerabilities.

Also documents the GitHub Action distribution model in `CLAUDE.md`: `uses: homeofe/supply-chain-guard@v5` now resolves to a floating `v5` branch (kept current by a new `update-major-branch` CI job via fast-forward push), and the GitHub Marketplace publishing limitation (web-UI only, not automatable).

## [5.2.34] - 2026-06-21
**Threat-intel update: Mastra npm scope takeover (Sapphire Sleet) + NastyC2 + crypto-javascript worm**

Three supply-chain threats ingested from the daily threat-intel sweep:

- **Mastra npm scope takeover (June 17, 2026)**: Microsoft attributes a large-scale npm compromise to Sapphire Sleet (BlueNoroff, DPRK) - the same actor behind the April 2026 axios hijack. A forgotten-contributor npm maintainer account (`ehindero`) was compromised and used to republish 141 packages across the `@mastra` scope (01:12-02:36 UTC), each gaining a single new dependency: `easy-day-js`, a dayjs clone. Its `postinstall` hook disables TLS certificate verification, contacts a dropper C2 at `23[.]254[.]164[.]92:8000` (`/update/49890878`), and downloads a cross-platform Node.js crypto-stealer RAT (RAT C2 `23[.]254[.]164[.]123:443`, both Hostwinds-hosted) that inventories 166 wallet browser extensions and harvests Chrome/Brave/Edge history. Added: `easy-day-js` (bare-name pattern), `easy-day-js@1.11.22` plus a representative subset of the 143 compromised `@mastra` package versions to `KNOWN_BAD_NPM_VERSIONS`, both C2 IPs, two SHA-256 hashes (stage-2 RAT + malicious tarball), the `ehindero`/`sergey2016` accounts, and matching `BUNDLED_FEED` entries (confidence 1.0). The clean precursor `easy-day-js@1.11.21` is deliberately not listed.
- **NastyC2 npm framework (June 18, 2026)**: three fully malicious npm packages (`node-ci-utils@2.1.4`, `win-env-setup@3.0.6`, `macos-ci-utils@1.0.0`) bundling NastyC2, a Rust post-exploitation implant with 80+ commands (credential harvesting, Active Directory attacks, container escape, cloud-metadata theft, fileless execution). Added as bare-name patterns and version-pinned blocklist/feed entries (confidence 0.9; source: The Hacker News ThreatsDay Bulletin).
- **crypto-javascript@4.2.5 (June 18, 2026)**: a self-propagating supply-chain worm spreading across Rust/Cargo, Python, CMake, and npm that drops a Monero cryptominer and the "Dirty Frag" Linux kernel LPE exploit. Version-pinned (common-sounding name) in `KNOWN_BAD_NPM_VERSIONS` and `BUNDLED_FEED` (confidence 0.9).

Deliberately not ingested this sweep: the Klue OAuth breach (Icarus), FortiBleed, the NGINX/Splunk CVEs, and the SocGholish takedown - none are package-ecosystem compromises with extractable, version-pinned IOCs. Two new `campaigns.test.ts` describe blocks cover the Mastra and NastyC2 signatures.

## [5.2.33] - 2026-06-14
**Security: fix devDependency vulnerabilities (vitest, esbuild)**

Dependabot flagged three advisories in the dev/test toolchain. All are `devDependencies` and none ship in the published npm tarball (`files[]` is limited to `dist`, `action.yml`, `README.md`, `LICENSE`, `socket.yml`), so consumers of the package were never exposed - but a security tool should not carry known-vulnerable dev deps.

- **vitest** bumped from `^3.0.0` to `^3.2.6`, resolving CVE-2026-47429 (critical). Stays within the 3.x line to avoid the breaking changes of the Dependabot-proposed 4.x major bump; all 799 tests pass unchanged.
- **esbuild** forced to `^0.28.1` via an `overrides` entry, resolving GHSA-gv7w-rqvm-qjhr (high) and GHSA-g7r4-m6w7-qqqr (low). vitest 3.x's transitive vite otherwise pins an older esbuild; the override pulls the patched build without a vitest major upgrade.
- `npm audit` now reports 0 vulnerabilities. Supersedes Dependabot PR #25.

Also adds `.supply-chain-guard.yml` (committed separately) with documented accepted-risk suppressions for the project's own self-scan: `GHA_OIDC_WRITE_PERM` and `WORKFLOW_SECRET_TO_UPLOAD_PATH` are by-design tradeoffs for npm Trusted Publishing, `LOCKFILE_ORPHANED_DEPENDENCY` is informational. Self-scan result: 0/100 clean.

## [5.2.32] - 2026-06-13
**Threat-intel update: Arch Linux AUR mass-hijack npm dropper (atomic-lockfile)**

One confirmed, cross-verified indicator ingested from the daily threat-intel sweep (sources: The Hacker News + BleepingComputer, June 12, 2026):

- **atomic-lockfile@1.4.2 (npm)**: fully malicious package pulled and executed by `preinstall` hooks added to 400+ hijacked Arch User Repository (AUR) build scripts. It installs a credential stealer and an eBPF rootkit on any machine that builds an affected AUR package. The version was published 2026-06-10 and removed by npm security 2026-06-12 (the registry now serves only the `0.0.1-security` holding placeholder), confirming the package had no legitimate history. Added to `MALICIOUS_PACKAGE_PATTERNS` (bare-name), `KNOWN_BAD_NPM_VERSIONS` (version 1.4.2), and `BUNDLED_FEED` (confidence 1.0).

Deliberately not ingested this sweep:

- **temp.sh** (named as the AUR campaign's HTTP exfiltration host): a legitimate public file-sharing service. Blocking it would false-positive on benign code, same rationale used to omit `i.ibb.co` previously.
- **alvr / premake-git** (named compromised AUR packages): legitimate upstream packages that were hijacked, in an ecosystem this scanner does not version-track; the names alone are not safe indicators.
- The single-source SHA-256 reported for the AUR payload was not cross-confirmed by a second source, so it was left out rather than risk a hallucinated hash.
- **TeamPCP "Phantom Gyp" wave** (`@vapi-ai/server-sdk`, SANS ISC diary 33060) and the **Miasma 73-Microsoft-repos worm** (Dark Reading) disclosed no exact compromised versions or extractable host IOCs beyond the `@redhat-cloud-services` coverage already shipped in v5.2.29.

1 new describe block in `campaigns.test.ts` covers the `atomic-lockfile` package-name pattern.

## [5.2.31] - 2026-06-11
**Threat-intel update: ThreatsDay Bulletin npm cluster (SStar Agent lure + ambar-src)**

Two fully-malicious npm packages and two malicious GitHub accounts ingested from the daily threat-intel sweep (source: The Hacker News ThreatsDay Bulletin, June 11, 2026):

- **tw-style-utils (npm)**: poisoned package that delivers the cross-platform `SStar Agent` RAT (Windows + macOS). Distributed through the `star45674/smart-contract-engineer-role` fake job-assignment lure (contagious-interview style), tracked as a malicious GitHub account.
- **ambar-src (npm)**: fully malicious package (Tenable) whose download count was artificially "pumped" to 50,000+ in three days to manufacture credibility.
- **antoniocastaldo1998 (GitHub account)**: hosts a malicious Android APK in its `app-scuola` repository.

Each package is malicious in its entirety, so the package name itself is the indicator: added to `MALICIOUS_PACKAGE_PATTERNS` and `BUNDLED_FEED` (confidence 0.9, single-source). The two GitHub accounts were added to `KNOWN_MALICIOUS_GITHUB_ACCOUNTS`.

Not ingested this sweep: the Shai-Hulud "Hades" Python variant against PyPI is the same Miasma family already covered in v5.2.29/v5.2.30, and the bulletin published no exact compromised package versions or extractable host IOCs (blocking bare names of otherwise-legitimate packages would false-positive on clean installs). The TeamPCP "Phantom Gyp" wave (SANS ISC diary 33060) named `@vapi-ai/server-sdk` as a victim but disclosed no exact bad version numbers. OnyxC2 stealer (a MaaS builder), the JDY IoT botnet, OceanLotus SPECTRALVIPER, and the Proto6 / `protobuf.js` RCE CVEs either yielded no extractable package/host IOCs or are outside the developer supply-chain scope.

1 new describe block in `campaigns.test.ts` covers the two package-name patterns and the two malicious-account references.

## [5.2.30] - 2026-06-09
**Threat-intel update: THN Weekly Recap npm/PyPI infostealer cluster**

Four fully-malicious throwaway packages ingested from the daily threat-intel sweep (source: The Hacker News Weekly Recap, June 8, 2026):

- **turbo-axios / faster-axios (npm)**: trojanized copies of `axios` whose `postinstall` hooks deploy Epsilon Stealer.
- **cms-store-ren (npm)**: exfiltrates harvested data to Telegram via an exposed bot API token.
- **parsimonius (npm + PyPI)**: typosquat of `parsimonious` deploying a Telegram-based backdoor (~2,474 downloads before removal).

Each package is malicious in its entirety, so the package name itself is the indicator: added to `MALICIOUS_PACKAGE_PATTERNS` (npm), `PYPI_TYPOSQUAT_PATTERNS` (the `parsimonius` PyPI typosquat), and `BUNDLED_FEED` (confidence 0.9, single-source).

Not ingested this sweep: the new Shai-Hulud "Hades" wave against 19 science-focused PyPI packages (Dynamo, Spateo, CoolBox, U-FISH, Napari-UFISH) was confirmed but the affected releases are bad versions of otherwise-legitimate packages and no exact version numbers were published, so blocking the bare names would false-positive on clean installs; its only listed C2 was `api.anthropic.com`, the legitimate Anthropic API host, which is intentionally not added (same call as v5.2.29). The Miasma worm hitting 73 Microsoft GitHub repositories is the same `Miasma: The Spreading Blight` campaign already covered in v5.2.29 (the named Microsoft / `icflorescu` repositories are victims, not malicious accounts). Rust-written IronWorm npm, NFCShare Android, C0XMO botnet, VerdantBamboo BRICKSTORM, and the LiteLLM `CVE-2026-42271` RCE flaw either yielded no extractable package/host IOCs or are outside the developer supply-chain scope.

1 new describe block in `campaigns.test.ts` covers the four package-name patterns.

## [5.2.29] - 2026-06-02
**Threat-intel update: Miasma / @redhat-cloud-services Mini Shai-Hulud variant**

One new campaign ingested from the daily threat-intel sweep (sources: BleepingComputer, Socket.dev, June 1, 2026):

- **Miasma / @redhat-cloud-services Mini Shai-Hulud variant (2026-06-01)**: BleepingComputer and Socket.dev disclosed that 32 packages under Red Hat's `@redhat-cloud-services` namespace were trojanized (96 versions) via a compromised Red Hat employee GitHub account abusing a GitHub Actions workflow to auto-publish backdoored versions. Payload is a Shai-Hulud descendant labelled `Miasma: The Spreading Blight`; the preinstall hook runs a ~4.2 MB `node index.js` that steals GitHub Actions secrets, AWS / GCP / Azure credentials, HashiCorp Vault tokens, Kubernetes SA tokens, npm and PyPI publishing tokens, SSH keys, Docker creds, GPG keys, and `.env` files into ~309 attacker-controlled GitHub repos. Added the `Miasma: The Spreading Blight` content-marker pattern, and the Socket-confirmed `@redhat-cloud-services/chrome@2.3.1` known-bad version (the namespace itself is deliberately NOT blocked - clean upstream versions remain legitimate).

Not ingested this sweep: DriveSurge ClickFix/FakeUpdates is web-traffic malvertising with no package IOCs; the Operation Dragon Weave / AdaptixC2 cluster, Dutch 17M-device residential-proxy takedown, and the various non-package CVEs (Windows Netlogon `CVE-2026-41089`, WP Maps Pro `CVE-2026-8732`, PAN-OS GlobalProtect `CVE-2026-0257`, the Linux kernel CIFSwitch privesc) are all outside the developer supply-chain scope. The `api.anthropic.com` endpoint that one threat-intel summary listed as a Miasma "C2 domain" was rejected as either summarizer hallucination or feed poisoning - it is the legitimate Anthropic API host and is intentionally not added.

1 new describe block in `campaigns.test.ts` covers the campaign-marker detection.

## [5.2.28] - 2026-06-01
**Threat-intel update: codexui-android Codex stealer, LiteLLM PyPI backdoor, vpmdhaj Sicoob/cloud-secret cluster**

Three new campaigns ingested from the daily threat-intel sweep (sources: Aikido, The Hacker News, Trail of Bits, Socket.dev, May 22 - June 1, 2026):

- **codexui-android Codex token stealer (2026-05-27)**: Aikido and The Hacker News disclosed a legitimate-looking Codex remote-UI npm package (~27K-29K weekly downloads) that since version `0.1.82` reads the OpenAI Codex auth file, XOR-encrypts with key `anyclaw2026`, base64-encodes and POSTs to `sentry[.]anyclaw[.]store/startlog`. Same endpoint is hit by the bundled Android apps "OpenClaw Codex Claude AI Agent" (`gptos.intelligence.assistant`) and "Codex" (`codex.app`) running the package in a PRoot sandbox. Added the C2 domain, the package name regex, 9 known-bad versions (`0.1.82`-`0.1.90`), and the publisher GitHub accounts `friuns2` / `BrutalStrike`.
- **LiteLLM PyPI compromise (2026-03-24, re-disclosed 2026-05-22)**: Trail of Bits' "We hardened zizmor" post detailed the TeamPCP-claimed compromise of `litellm` `1.82.7` / `1.82.8` on PyPI, originating from a poisoned Trivy step in LiteLLM's own CI/CD security workflow. A `litellm_init.pth` auto-runs on every Python startup; three-stage payload (50+ category credential harvester with RSA-4096 + AES-256 hybrid encryption, Kubernetes lateral-movement toolkit, persistent backdoor) exfils to `models[.]litellm[.]cloud` and polls `checkmarx[.]zone` (Checkmarx-brand abuse to bypass DNS allowlists) every 50 minutes. Added the two C2 domains and the two known-bad PyPI versions.
- **vpmdhaj Sicoob/Cloud-Secret cluster (2026-05-28)**: Socket via The Hacker News reported a single actor (`vpmdhaj`, `a39155771[@]gmail[.]com`) running two parallel waves. Five NuGet versions `Sicoob.Sdk` `2.0.0`-`2.0.4` impersonate a C# SDK for Brazilian cooperative bank Sicoob and exfiltrate PFX certificates + client IDs + PFX passwords to a hardcoded Sentry DSN. Fourteen npm typosquats of OpenSearch / ElasticSearch / DevOps / env-config libraries harvest AWS creds, HashiCorp Vault tokens, npm tokens, CI/CD secrets through preinstall hooks; C2 auth via hardcoded `X-Secret` header `l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1`. Added 5 NuGet + 14 npm IOCs, the GitHub org `Sicoob-Cooperativa`, the contributor `joaobcdev`, and 2 regex families (scoped `@vpmdhaj/*` + unscoped typosquats).

3 new describe blocks in `campaigns.test.ts` cover the surface-level detections (C2 domains + package-name patterns + attacker accounts).

## [5.2.27] - 2026-05-28
**Threat-intel update: ACR Stealer fake-Claude page, Malware-Slop npm infostealer**

Two new campaigns ingested from the daily threat-intel sweep (sources: SANS ISC, The Hacker News / OX Security, May 26-27, 2026):

- **ACR Stealer fake Claude page (2026-05-26)**: per SANS ISC diary 33018, Claude-impersonation pages pushed via Google Search ads serve a corrupted zip that fetches a PowerShell loader leading to ACR Stealer. Added 4 attacker-controlled base domains (`fairpoint29[.]com`, `primemetricsa[.]com`, `creativecommunityinfo[.]art`, `enhanceblabber[.]cc`) and 3 component SHA-256 hashes to `ioc-blocklist.ts` + `BUNDLED_FEED`. Base domains are stored (not the reported random subdomains) so the entries survive subdomain rotation. The legitimate ImgBB host `i[.]ibb[.]co` (abused to stage `init-block.jpg`) is deliberately NOT listed, to avoid mass false positives.
- **Malware-Slop npm infostealer (2026-05-27)**: per OX Security via The Hacker News, npm package `mouse5212-super-formatter` (~676 downloads) masquerades as an archive deployment-sync utility, authenticates to GitHub and recursively uploads files from the Claude AI user directory (`/mnt/user-data`) into repos created under attacker account `unplowed3584` (now removed). Added the package to `MALICIOUS_PACKAGE_PATTERNS` + `BUNDLED_FEED` and the account to `KNOWN_MALICIOUS_GITHUB_ACCOUNTS`.

Not ingested this sweep: the GlassWorm C2 takedown (CrowdStrike/Google/Shadowserver) is defensive news with no new blockable indicators, and BTMOB RAT is an Android banking trojan outside the developer supply-chain scope.

2 new describe blocks in `campaigns.test.ts` cover the surface-level detections (C2 domain + component hash + attacker account + malicious package name).

## [5.2.26] - 2026-05-25
**SLSA verifier recognises `npm publish --provenance` + OIDC as Level 3**

The SLSA verifier's L3 patterns required the literal string `slsa-framework/slsa-github-generator` in a workflow. That predated npm's `--provenance` flag (added in npm 9.5, mandatory under Trusted Publishing since npm 11.5), which produces Sigstore-signed, Rekor-logged provenance bound to the GitHub Actions OIDC identity - cryptographically the same L3 guarantees the slsa-github-generator reusable workflow produces, just specialised for npm artifacts.

New L3 detection path in `slsa-verifier.ts`: a workflow corpus containing both
- `npm publish ... --provenance`, AND
- `id-token: write` permission

is recognised as Level 3. Without `id-token: write` the publish would fail at runtime, so the OIDC permission is required defence-in-depth to ensure the workflow can actually mint provenance, not just that someone typed the flag into a non-functional config.

The `SLSA_UNSIGNED_ARTIFACTS` recommendation now describes both L3 paths (npm-native vs. slsa-github-generator) so projects pick the one that fits their ecosystem.

4 new tests in `slsa-verifier.test.ts` cover: combined `--provenance` + OIDC returns L3, `--provenance` alone stays at L2, OIDC alone stays at L1, and the two signals split across separate workflow files in the same `.github/workflows/` directory still register as L3.

Expected impact on the self-scan: the `SLSA_UNSIGNED_ARTIFACTS` INFO finding drops because our own `ci.yml` already has the L3 npm-native combination since v5.2.20.

## [5.2.25] - 2026-05-25
**Threat-intel update: TrapDoor, Polymarket typosquats, durabletask, Megalodon throwaways**

Five new campaigns ingested from the daily threat-intel sweep (sources: The Hacker News, SANS ISC, BleepingComputer, May 22-25, 2026):

- **TrapDoor cross-ecosystem credential stealer (2026-05-25)**: single actor `ddjidd564` pushing 34+ malicious packages across npm (21), PyPI (7), and Crates.io (6). Targets AI / DeFi / Web3 / Sui Move tooling. Dead-drop hosted at `ddjidd564[.]github[.]io`. Added 1 domain, 1 GitHub account, 34 package IOCs, 2 regex families (npm + PyPI), 2 test cases.
- **Mini Shai-Hulud / TeamPCP durabletask (2026-05-24)**: per SANS ISC diary 33016, three malicious versions (`1.4.1`, `1.4.2`, `1.4.3`) of the officially Microsoft-published `durabletask` PyPI package were republished by the TeamPCP campaign. First confirmed compromise of an upstream Microsoft-signed package in this wave. Added to `KNOWN_BAD_PYPI_VERSIONS` and `BUNDLED_FEED`.
- **Polymarket impersonation (2026-05-22)**: npm publisher `polymarketdev` pushed 9 typosquats of the Polymarket SDK (`polymarket-trading-cli`, `-terminal`, `-trade`, `-auto-trade`, `-copy-trading`, `-bot`, `-claude-code`, `-ai-agent`, `-trader`). Wallet-key exfiltration via Cloudflare Worker at `polymarketbot[.]polymarketdev[.]workers[.]dev/v1/wallets/keys`. Added 1 domain, 1 GitHub account, 9 package IOCs, 1 regex family.
- **Megalodon throwaway accounts (2026-05-22)**: three previously unattributed GitHub throwaway accounts (`rkb8el9r`, `bhlru9nr`, `lo6wt4t6`) used in the 5,718-commit workflow-injection blast against 5,561 repos. C2 (`216[.]126[.]225[.]129:8443`) was already in v5.2.24. Added the three accounts to `KNOWN_MALICIOUS_GITHUB_ACCOUNTS`.

3 new describe blocks in `campaigns.test.ts` cover the surface-level detections (C2 domain + attacker GitHub account).

## [5.2.24] - 2026-05-24
**`RISK_TRAJECTORY_UNSTABLE` no longer flags monotone improvement as instability**

The risk-forecast engine used `Math.abs(slope) > 5` to detect "volatile risk", which conflated two opposite situations:

- Score rising fast (real degradation) → should fire
- Score falling fast (active remediation) → should NOT fire, that is exactly what we want
- Score bouncing back and forth (true volatility) → should fire

The v5.2.23 self-scan reported "slope -13.9/scan, highly volatile" after six consecutive releases each fixing real bugs - a strict monotone decrease being labelled as instability.

The detection is now split into orthogonal concerns:

- `RISK_TRAJECTORY_DEGRADING` (severity high): `slope > +5`, score consistently rising
- `RISK_TRAJECTORY_UNSTABLE` (severity medium): high stdev around the linear-fit trend **and** at least 2 direction reversals in the sequence (true oscillation, not just non-linear improvement)
- Fast improvement (`slope < -5` with no oscillation): silent, surfaced in the score itself

5 new tests in `bugfix-v5_2_24.test.ts` verify:
- Strict monotone decrease (including the v5.2.18-v5.2.23 release trajectory) does NOT fire UNSTABLE
- Fast-rising score DOES fire DEGRADING
- Real oscillation (e.g. `[20, 80, 25, 75, 30, 70]`) DOES fire UNSTABLE
- Stable flat trajectory fires neither

Expected impact on the self-scan: drops the spurious `RISK_TRAJECTORY_UNSTABLE` finding. Score should fall from 17/MEDIUM to roughly 5-10/LOW.

## [5.2.23] - 2026-05-24
**Fix `WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH` false positive on `npm@latest`**

The unpinned-action detector in `workflow-modeler.ts` was firing on any `@latest` / `@main` / `@master` / `@dev` substring anywhere in a workflow file - including the `npm install -g npm@latest` step that v5.2.20 introduced as part of the OIDC trusted-publishing setup. That's a Node toolchain install, not a GitHub Action reference.

The regex is now scoped to actual `uses: <action>@<branch>` declarations using a line-anchored, case-insensitive multiline match:

```ts
/^\s*-?\s*uses:\s+\S+@(?:main|master|latest|dev)\b/im
```

4 new tests in `bugfix-v5_2_23.test.ts` verify:
- `npm install -g npm@latest` no longer triggers
- Real `uses: actions/checkout@main` / `@master` / `@latest` / `@dev` still triggers
- Commit-SHA pinning (the v5.2.22 fix) stays clean

Expected impact on the self-scan: the last false-positive CRITICAL is gone. Remaining 2 mediums (`GHA_OIDC_WRITE_PERM` for Trusted Publishing, `WORKFLOW_SECRET_TO_UPLOAD_PATH` for `secrets.GITHUB_TOKEN` access in the GitHub Release step) are honest by-design tradeoffs.

## [5.2.22] - 2026-05-24
**Self-scan polish: comment-aware GHA scan, pinned actions, fix changelog self-trigger**

Three follow-up fixes to the v5.2.21 self-scan:

- **`github-actions-scanner` strips YAML comments before pattern matching**. The previous version flagged the literal text `id-token: write` inside an OIDC-explanation comment of `ci.yml` as a real `GHA_OIDC_WRITE_PERM` finding. New `stripYamlComment()` helper removes `# ...` portions before regex matching while preserving `#` inside quoted strings. 4 new tests in `bugfix-v5_2_22.test.ts`.
- **`.github/workflows/ci.yml` actions pinned to commit SHAs**. `actions/checkout` and `actions/setup-node` were on `@v4` (mutable major-tag); release pipelines should pin to immutable commit SHAs (`actions/checkout@34e11487...` and `actions/setup-node@49933ea5...`) to defend against tag-rewriting attacks. Comments preserve `# v4` for human readability. Fixes the legitimate `WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH` finding.
- **v5.2.21 changelog entry rephrased to remove a self-trigger**. The original entry literally quoted the trigger phrase it was documenting the removal of, which then re-triggered `CAMPAIGN_CLAUDE_LURE` and `CAMPAIGN_AI_TOOL_LURE` on the new entry. The new wording explains the change abstractly without quoting the offending collocation.

Expected impact on supply-chain-guard's own self-scan: from 3 critical + 3 medium down to 0 critical + 1-2 medium. Remaining: 1x `GHA_OIDC_WRITE_PERM` (the real one in the publish job - by design for Trusted Publishing) and `WORKFLOW_SECRET_TO_UPLOAD_PATH` (legitimate `secrets.GITHUB_TOKEN` access for `gh release create`). Both are honest acceptable-risk findings.

## [5.2.21] - 2026-05-24
**Architectural fix: source-marker patterns no longer fire on documentation files**

The v5.2.20 self-scan still scored 100/100 CRITICAL despite all previous fixes, with 28 critical + 10 high findings - **all** triggered by the project's own README documenting the patterns and IOC strings that the scanner detects. Same problem applies to every threat-intel blog post or security research write-up scanned by supply-chain-guard.

Root cause: campaign signatures, IOC hashes, and infostealer markers exist in **malware payloads** (source code), not in **markdown documentation**. The patterns did not differentiate.

Fix: a new `BENIGN_DOC_FILES` constant (`/\.(md|markdown|txt|rst)$/i`) is now combined with `SCANNER_SRC` into `SCANNER_SRC_OR_DOCS`. All source-marker patterns that previously used `notFilePattern: SCANNER_SRC` now use the combined regex - 47 patterns across `CAMPAIGN_PATTERNS`, `CAMPAIGN_PATTERNS_V2`, `INFOSTEALER_PATTERNS`, `C2_EXTENDED_PATTERNS`, `FILE_PATTERNS`, `OBFUSCATION_*`, `IAC_PATTERNS`, `SECRETS_PATTERNS`, `PROVENANCE_PATTERNS`. The six inline-merged `notFilePattern` regexes (`VIDAR_BROWSER_THEFT`, `PROXY_BACKCONNECT`, `DROPPER_TEMP_EXEC`, `PROXY_HANDLER_TRAP`, `BEACON_INTERVAL_FETCH`, `MINER_CONFIG_KEYS`) were extended manually.

`checkIOCBlocklist()` (`src/ioc-blocklist.ts`) and `checkThreatIntel()` (`src/threat-intel.ts`) now early-return for `.md/.markdown/.txt/.rst` paths.

`LURE_PATTERNS` and `PROMPT_INJECTION_PATTERNS` are explicitly excluded from the architectural fix - they target documentation by design (malicious README lures, prompt-injection attacks on AI agents) and continue to fire on `.md` files within their `onlyFilePattern` scope.

README cosmetic defang for the residual self-flags:
- Solana RPC reference in v5.2.2 changelog defanged to `api[.]mainnet-beta[.]solana[.]com`
- Prompt-injection token examples in v5.2.19 changelog + "What It Detects" section HTML-encoded (`&lt;system-reminder&gt;`, `&#91;INST&#93;`) - markdown renders them normally but the raw text no longer contains literal `<`/`[` characters that match the patterns
- The v5.2.19 changelog sentence describing the WebFetch tag-leakage incident was rephrased to avoid triggering `CAMPAIGN_CLAUDE_LURE` / `CAMPAIGN_AI_TOOL_LURE`. The original phrasing combined "Claude Code" with a verb the lure-detection regex looks for; the new phrasing describes the same incident without that verb collocation.

13 new regression tests in `src/__tests__/bugfix-v5_2_21.test.ts` enforce the doc-exclusion across all affected pattern arrays and the two scanners. Test count: 752 (was 739).

Expected impact on supply-chain-guard's own self-scan: drops from 28 critical + 10 high to roughly 0 critical + 0 high. Remaining findings are by-design GitHub Actions choices (`GHA_OIDC_WRITE_PERM` and `WORKFLOW_SECRET_TO_UPLOAD_PATH` for Trusted Publishing) and project handoff notes legitimately referencing Solana - addressable via project policy file if desired, but not bugs.

## [5.2.20] - 2026-05-24
**Pattern bug fixes uncovered by the v5.2.19 self-scan**

Running supply-chain-guard against its own repository surfaced five structural false-positives and detection gaps. Each is now fixed at the source:

- **SOLANA_MAINNET self-flagged `src/solana-monitor.ts`** - the pattern had only `notTestFile: true` and no `notFilePattern`. `SCANNER_SRC` regex extended to include `solana-monitor`, `solana-watchlist`, `slsa-verifier`, and `sbom-generator`; `SOLANA_MAINNET` now sets `notFilePattern: SCANNER_SRC` like other scanner-internal-aware patterns do.
- **README lure findings reported twice with different recommendations** - `LURE_PATTERNS` was being executed both by the general `checkFilePatterns` sweep and by the dedicated `scanReadmeLures` path, producing one finding from each with subtly different recommendation text. `LURE_PATTERNS` removed from `checkFilePatterns`; `scanReadmeLures` routing in `scanDirectory` expanded from `readme*` only to the full doc-file family (README / CHANGELOG / CONTRIBUTING / DESCRIPTION / release-notes) so coverage is unchanged.
- **`CRITICAL_FINDING_NO_OWNER` cascaded HIGH findings on every critical FP** - the meta-governance rule fired by default even on projects that never opted into the triage system. Now only fires when at least one triage decision has been recorded (`decisions.length > 0`).
- **`SLSA_NO_PROVENANCE` misreported repos using `npm publish --provenance`** - the SLSA Level-2 detection list recognised `slsa-github-generator`, `cosign`, and `attest-build-provenance` actions but not the modern npm-native provenance flag (standard since npm 9, mandatory with Trusted Publishing since 11.5). Added `/npm\s+publish[^\n]*--provenance/i` to `SLSA_LEVEL2_PATTERNS`.
- **`LOCKFILE_ORPHANED_DEPENDENCY` recommendation was wrong for npm v7+** - the message told users to run `npm prune`, which does not remove transitive dependencies from npm v7+ flat lockfiles (they are present by design). Recommendation rewritten to explain npm v7+ behaviour and direct users to verify publishers / inspect `npm ls <name>` instead.
- 15 new regression tests in `src/__tests__/bugfix-v5_2_20.test.ts` plus updated `triage-engine.test.ts` cover all five fixes. Total test count: 739 passing.

## [5.2.19] - 2026-05-24
**New detection: prompt injection against downstream AI coding agents**

Adds five new patterns under `PROMPT_INJECTION_PATTERNS` (`src/patterns.ts`) that flag LLM-control tokens and role markers embedded in package documentation (README, CHANGELOG, CONTRIBUTING, DESCRIPTION, release notes). These tokens target the AI coding agent that reads the README on the human developer's behalf, not the human - a growing supply-chain attack vector as LLM coding tools become standard.

- `PROMPT_INJECTION_SYSTEM_REMINDER` - Anthropic/Claude Code harness tags (`&lt;system-reminder&gt;`, `&lt;system-prompt&gt;`, `&lt;system-instruction&gt;`)
- `PROMPT_INJECTION_CHATML` - OpenAI/Llama/Mistral/Qwen ChatML tokens (`&lt;|im_start|&gt;`, `&lt;|im_end|&gt;`, `&lt;|im_sep|&gt;`)
- `PROMPT_INJECTION_INST_TAG` - Mistral/Llama instruction tags (`&#91;INST&#93;`, `&#91;/INST&#93;`)
- `PROMPT_INJECTION_ROLE_TOKEN` - generic role tokens used by Phi, Gemma, Granite and others (`&lt;|system|&gt;`, `&lt;|user|&gt;`, `&lt;|assistant|&gt;`, `&lt;|developer|&gt;`, `&lt;|tool|&gt;`)
- `PROMPT_INJECTION_OVERRIDE_PROSE` - natural-language jailbreak phrasing ("ignore previous instructions", "disregard the system prompt", etc.) requiring imperative sentence-start form to avoid false positives in security docs that discuss the attack
- All five are severity HIGH, scoped to README-style files only (`onlyFilePattern`), exclude scanner source (`notFilePattern: SCANNER_SRC`) and test files. 39 new tests in `src/__tests__/prompt-injection-patterns.test.ts`.
- Motivated by a real WebFetch tag-leakage incident in the daily threat-intel routine on 2026-05-24: an internal Claude Code summarisation helper accidentally surfaced its own harness tag inside a fetched-content summary, demonstrating exactly the failure mode a hostile package could weaponise.

## [5.2.18] - 2026-05-24
**Threat intel: Laravel-Lang DebugElevator + Packagist 8-package GitHub-binary attack (May 23, 2026)**

Two coordinated Composer / Packagist supply-chain attacks disclosed within hours of each other on 2026-05-23.

- **Laravel-Lang DebugElevator** (The Hacker News and BleepingComputer, 2026-05-23): four Composer packages in the `laravel-lang` namespace (`laravel-lang/lang`, `laravel-lang/http-statuses`, `laravel-lang/attributes`, `laravel-lang/actions`) had their GitHub version tags abused to republish roughly 700 historical versions, each carrying a malicious `src/helpers.php` containing a ~5,900-line PHP credential-stealing framework that exfiltrates to `flipboxstudio[.]info/exfil`. PDB-style references in the artifacts mention developer handles `Mero` and `claude`. Added the C2 domain plus two payload SHA-256 hashes (`f0d912c1a72e533417d5e158bb9755f848ec678b6448ae7c8fb6e87da78a3053`, `23e779555c21beaed6ae8f1f298daf9b00d603f1a6716ce329332aadcb80fbe2`) and four `composer:` package IOCs to the bundled feed, plus a new campaign test block.
- **Packagist `parikhpreyash4` binary attack** (The Hacker News, 2026-05-23): coordinated hit on eight Composer packages (`moritz-sauer-13/silverstripe-cms-theme`, `crosiersource/crosierlib-base`, `devdojo/wave`, `devdojo/genesis`, `katanaui/katana`, `elitedevsquad/sidecar-laravel`, `r2luna/brain`, `baskarcm/tzi-chat-ui`) whose dev branches had `package.json` postinstall hooks added that pull a Linux ELF (`gvfsd-network`) from `github[.]com/parikhpreyash4/systemd-network-helper-aa5c751f` and execute it from `/tmp/.sshd`. Mixing JS toolchain hooks into PHP projects let the payload sidestep Composer-side review. Added the attacker GitHub account to the malicious-accounts list, the eight `composer:` package IOCs to the bundled feed, and a campaign test block.

## [5.2.17] - 2026-05-23
**Threat intel: Megalodon GitHub workflow injection + DPRK OtterCookie Node.js stealer (May 22, 2026)**

Two May 22 disclosures, both pivoting on adjacent IPs in `216[.]126[.]225[.]0/24` (likely shared DPRK-adjacent infrastructure).

- **Megalodon GitHub Actions workflow injection** (The Hacker News, 2026-05-22): an automated campaign pushed 5,718 malicious commits to 5,561 GitHub repositories in a six-hour window. The attacker forged author identities as `build-bot`, `auto-ci`, `ci-bot`, and `pipeline-bot`, then injected GitHub Actions workflows that ran base64-encoded bash to exfiltrate CI env vars, AWS / GCP credentials, SSH private keys, OIDC tokens, and Docker / Kubernetes / Terraform configs to `216[.]126[.]225[.]129:8443`. Added the C2 IP plus a new `MEGALODON_C2_ENDPOINT` rule that catches the endpoint with or without the port.
- **DPRK OtterCookie Node.js stealer** (SANS ISC diary 33006, 2026-05-22): sample uploaded to VirusTotal as `extracted-decoded.js`; obfuscator.io-style obfuscation; targets 41 crypto-wallet Chrome extension IDs (MetaMask, Phantom, Coinbase, Ledger) plus 200+ sensitive file patterns (`.env`, `.pem`, `.p12`, `.jks`, SSH keys, seed phrases) across Windows-via-WSL, macOS, and Linux. C2 over three ports on `216[.]126[.]225[.]243`: 8085 (browser creds), 8086 (file uploads), and 8087 with WebSocket reverse shell at `/api/notify`. Sample SHA-256 `049300aa5dd774d6c984779a0570f59610399c71864b5d5c2605906db46ddeb9`; highly specific hardcoded HMAC-SHA256 key `SuperStr0ngSecret@)@^`. Added two new rules (`OTTERCOOKIE_HMAC_KEY`, `OTTERCOOKIE_C2_ENDPOINT`) plus IP, URL, and hash IOCs, and a campaign test block.

## [5.2.16] - 2026-05-22
**Threat intel: Checkmarx Jenkins plugin version correction + postmark-mcp hostile MCP server**

Two updates driven by independent disclosures aggregated through 2026-05-22.

- **Checkmarx Jenkins AST plugin (correction)**: SANS ISC diary 32994 (2026-05-18) and the official Checkmarx confirmation from 2026-05-11 establish that the tampered build was Marketplace version `2026.5.09`, exposed 2026-05-09 01:25 UTC to 2026-05-10 08:47 UTC. The last known-good build was `2.0.13-829.vc72453fa_1c16` (2025-12-17), and the remediated builds are `2.0.13-848.v76e89de8a_053` and `2.0.13-847.v08c0072b_2fd5`. The bundled threat-intel entry has been corrected from the prior placeholder version label, which was the last known-good build rather than the rogue version.
- **postmark-mcp hostile MCP server**: First documented in-the-wild malicious MCP server (Sep 2025), re-disclosed via Bishop Fox's "Otto-Support - Supply Chain Risks in MCP Servers" post on 2026-05-13. Version `1.0.16` introduces a hidden BCC of every outbound email to an attacker-controlled address while preserving the published tool name, schema, and behavior; versions through `1.0.15` are clean. Added to `KNOWN_BAD_NPM_VERSIONS` and the bundled threat-intel feed, plus a new campaign test.

## [5.2.15] - 2026-05-20
**Threat intel: Mini Shai-Hulud @antv + Nx Console + actions-cool triple wave (May 18-19, 2026)**

TeamPCP launched a coordinated triple supply-chain wave over 18-19 May 2026, all converging on the same exfiltration endpoint `t[.]m-kosche[.]com` (masquerading as an OpenTelemetry traces collector).

- **@antv ecosystem (npm)**: compromised maintainer account `atool` pushed 637 malicious versions across 317 packages in a 22-minute burst (01:39-02:18 UTC on 2026-05-19). Specific versions added: `@antv/g2@5.5.8`/`5.6.8`, `@antv/g6@5.2.1`/`5.3.1`, `echarts-for-react@3.1.7`/`3.2.7`, `timeago.js@4.1.2`/`4.2.2`. Payload: 498KB obfuscated Bun `index.js` (SHA-256 `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`).
- **Nx Console (VS Code)**: `nrwl.angular-console@18.95.0` published 2026-05-18 (exposure window 12:36-12:47 UTC) dropped a multi-stage credential stealer from an orphan commit `558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2` in the official `nrwl/nx` repo. Persistence: `~/.local/share/kitty/cat.py` Python daemon + `com.user.kitty-monitor` LaunchAgent / `kitty-monitor.service`. Dead-drop polls GitHub Search with marker query `firedalazer`. Hashes: VSIX `1a4afce3...`, `main.js` `b0cefb66...`, `index.js` `e7347d90...`, dropper `package.json` `43f2b001...`.
- **actions-cool GitHub Actions**: all tags of `actions-cool/issues-helper` (53 imposter commits) and `actions-cool/maintain-one-comment` (15 imposter commits) redirected to malicious payloads that read `Runner.Worker` process memory to harvest in-flight CI/CD secrets, then exfil over HTTPS to the same `t[.]m-kosche[.]com` C2.
- New `ANTV_WAVE_KITTY_PERSISTENCE`, `ANTV_WAVE_FIREDALAZER`, `ANTV_WAVE_OTEL_C2` rules in `src/patterns.ts`; new campaign tests in `src/__tests__/campaigns.test.ts`.

## [5.2.14] - 2026-05-19
**Threat intel: Phantom Bot DDoS npm infostealer + Mini Shai-Hulud TanStack follow-up (May 2026)**

Leaked Shai-Hulud worm source code was re-weaponized over the weekend of 2026-05-17 by npm publisher `deadcode09284814`. Four packages (`chalk-tempalte`, `@deadcode09284814/axios-util`, `axois-utils`, `color-style-utils`) shipped an infostealer plus a Golang Phantom Bot DDoS module (HTTP / TCP / UDP flood and TCP reset). Combined 2,678 downloads before takedown.

- C2 over localhost.run tunnels `87e0bbc636999b[.]lhr[.]life` and `edcf8b03c84634[.]lhr[.]life`, plus direct TCP to `80[.]200[.]28[.]28:2222`
- `deadcode09284814` added to known malicious GitHub / npm accounts; four packages added to `MALICIOUS_PACKAGE_PATTERNS`
- Follow-up IOCs from SANS ISC diary 32994 for the TanStack wave: `seed1[.]getsession[.]org` (second Session messenger exfil node), `router_init.js` payload SHA-256 `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, staging forks `github[.]com/voicproducoes` and `github[.]com/zblgg`
- New campaign tests for both clusters in `src/__tests__/campaigns.test.ts`

## [5.2.13] - 2026-05-16
**Threat intel: node-ipc credential stealer (May 2026)**

Maintainer email hijack of `atlantis-software[.]net` (re-registered 2026-05-07) led to malicious `node-ipc` releases `9.1.6`, `9.2.3`, and `12.0.1`.

- DNS exfiltration domain `sh[.]azurestaticprovider[.]net` (IP `37[.]16[.]75[.]69`); payload `node-ipc.cjs` SHA-256 `96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144`
- `12.0.1` uses hash-targeted activation and harvests 90+ credential categories
- Domains, IP, hash, and npm package IOCs added to bundled threat-intel feed

## [5.2.12] - 2026-05-14
**Threat intel: Mini Shai-Hulud TanStack / UiPath / Mistral compromise (May 2026)**

Continuation of the Mini Shai-Hulud worm via the TanStack ecosystem (CVE-2026-45321, CVSS 9.6).

- 3 C2 domains (`filev2[.]getsession[.]org`, `api[.]masscan[.]cloud`, `git-tanstack[.]com`) and 1 C2 IP (`83[.]142[.]209[.]194`)
- 9 compromised npm package families: OpenSearch (4 versions), Squawk (3), TallyUI (2)
- 2 compromised PyPI packages: `guardrails-ai@0.10.1`, `mistralai@2.4.6`

## [5.2.11] - 2026-05-12
**Threat intel: Checkmarx Jenkins AST plugin + MacSync Claude variant (May 2026)**

- Checkmarx Jenkins AST Plugin compromise by TeamPCP / Mr_Rot13 (malicious version `2.0.13-829.vc72453fa_1c16`). `Mr_Rot13` and `TeamPCP` added to known malicious GitHub accounts.
- MacSync Stealer Claude.ai / Google Ads variant: 3 new C2 domains (`customroofingcontractors[.]com`, `bernasibutuwqu2[.]com`, `briskinternet[.]com`) plus loader SHA-256 `ed5ed79a...` and payload SHA-256 `a833ad98...`
- New campaign tests for both clusters in `src/__tests__/campaigns.test.ts`

## [5.2.10] - 2026-05-10
**Threat intel: JDownloader compromise + fake OpenAI HF repo (May 2026)**

- JDownloader site compromise (2026-05-06 to 2026-05-07): Python RAT installers via `parkspringshotel[.]com`, `auraguest[.]lk`, `checkinnhotels[.]com`; bogus "Zipline LLC" and "The Water Team" signers; Linux ELF package plus systemd-exec
- Fake OpenAI Privacy Filter on Hugging Face: `Open-OSS/privacy-filter` trended; `loader.py` plus `start.bat` fetch sefirah infostealer (C2 `recargapopular[.]com`)

## [5.2.9] - 2026-05-09
**Threat intel: TCLBANKER Brazilian banking trojan (May 2026)**

REF3076 actor distributes trojanized `LogiAiPromptBuilder.exe` MSI; sideloads `screen_retriever_plugin.dll`; self-spreads via WhatsApp / Outlook worm modules; targets 59 banks, fintech platforms, and crypto exchanges.

- C2 domains: `campagna1-api[.]ef971a42[.]workers[.]dev`, `documents[.]ef971a42[.]workers[.]dev`, `mxtestacionamentos[.]com`
- C2 IP: `191[.]96[.]224[.]96`
- 4 new SHA-256 hashes added to bundled threat-intel feed
- 4 new campaign tests in `src/__tests__/campaigns.test.ts`

## [5.2.8] - 2026-05-08
**Threat intel: ZiChatBot PyPI + Beagle backdoor (May 2026)**

Two fresh May 2026 supply-chain campaigns are now signatured.

- **ZiChatBot PyPI campaign** - Three malicious PyPI packages (`uuid32-utils`, `colorinal`, `termncolor`) drop `terminate.dll` (Windows) / `terminate.so` (Linux) and abuse Zulip REST APIs as C2. Suspected APT32/OceanLotus link. New rule `ZICHATBOT_PACKAGE` in `src/patterns.ts`, `MALICIOUS_PACKAGE_PATTERNS` entries, and bundled threat-intel `package` IOCs.
- **Beagle backdoor / fake Claude AI site** - Drive-by from `claude-pro[.]com` delivers a 505MB ZIP with DonutLoader plus DLL sideloading via `NOVupdate.exe` + `avk.dll`, calling out to `license[.]claude-pro[.]com` (`8[.]217[.]190[.]58`). Domains and IP added to `KNOWN_C2_DOMAINS` / `KNOWN_C2_IPS` plus bundled threat-intel feed.
- 6 new tests in `src/__tests__/campaigns.test.ts`.

## [5.2.7] - 2026-05-08
**Threat intel: DAEMON Tools QUIC RAT supply-chain attack (May 2026)**

- Trojanized DAEMON Tools installers (versions 12.5.0.2421-12.5.0.2434) distributed via official website since 2026-04-08
- Selective second-stage QUIC RAT deployed to gov/scientific/manufacturing hosts in Russia, Belarus, Thailand
- C2 domain `env-check[.]daemontools[.]cc` added to `KNOWN_C2_DOMAINS` + threat-intel feed
- Suspected Chinese-speaking adversary; patched in version 12.6.0.2445

## [5.2.6] - 2026-05-08
**Threat intel: CanisterSprawl, BufferZoneCorp, MacSync, EtherRAT (May 2026)**

- **CanisterSprawl** - TeamPCP Update 008 with ICP canister-based C2 (`whereisitat[.]lucyatemysuperbox[.]space`)
- **xinference PyPI hijack** - Versions 2.6.0-2.6.2 (TeamPCP credential stealer)
- **BufferZoneCorp** - 7 poisoned Ruby `knot-*` sleeper gems + 9 Go modules
- **MacSync Stealer** - Homebrew malvertising via `glowmedaesthetics[.]com`
- **EtherRAT** - GitHub facade repos with Ethereum smart contract C2, fallback IP `135[.]125[.]255[.]55`

## [5.2.5] - 2026-05-01
**Threat intel: Mini Shai-Hulud / TeamPCP supply chain worm (April 2026)**

- SAP CAP npm hijacks: `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, `mbt@1.2.48`
- Intercom npm hijack: `intercom-client@7.0.4`
- PyTorch Lightning PyPI hijack: `lightning@2.6.2/2.6.3`
- Worm marker "A Mini Shai-Hulud has Appeared", Bun-based preinstall hook fingerprint

## [5.2.4] - 2026-04-30
**Threat intel: DPRK @validate-sdk/v2 + LofyGang / LofyStealer (April 2026)**

Two fresh April 2026 supply-chain campaigns are now signatured.

- **DPRK AI-inserted npm malware** — `@validate-sdk/v2` was inserted into a victim project as a dependency by the Claude Opus LLM during a social-engineering operation attributed to North Korean actors. New rule `DPRK_VALIDATE_SDK` in `src/patterns.ts` plus a `MALICIOUS_PACKAGE_PATTERNS` entry, a bundled threat-intel `package` IOC, and a recommendation to audit AI-suggested dependencies.
- **LofyGang / LofyStealer (aka GrabBot)** — Brazilian crew resurfaces after three years targeting Minecraft players with a new infostealer disguised as Minecraft hacks. New rules `LOFYSTEALER_MARKER` and `LOFYGANG_MINECRAFT_LURE` in `src/patterns.ts`, plus threat-intel `package` IOCs for the family aliases.
- 5 new tests in `src/__tests__/campaigns.test.ts`.

## [5.2.3] - 2026-04-26
**Documentation catch-up** — bumps version strings in `src/cli.ts`, `src/reporter.ts` (text header, SARIF, SBOM, HTML footer) that were stuck at `5.2.0` / `5.1.0` since the v5.2.1 and v5.2.2 releases. No behavior change.

## [5.2.2] - 2026-04-26
**Solana monitor: rate-limit-aware RPC client** — closes [#21](https://github.com/homeofe/supply-chain-guard/issues/21).

The public Solana RPC (`api[.]mainnet-beta[.]solana[.]com`) returns HTTP 429 and JSON-RPC error `-32005` when its per-IP quota is exceeded. Previously the monitor surfaced these as fatal poll errors and skipped the interval. Now `solanaRpc()` retries with exponential backoff and recovers automatically.

- **Detection**: HTTP 429, JSON-RPC code `-32005`, or message heuristics (`rate.?limit`, `too many requests`, `429`, `-32005`)
- **Backoff**: exponential 1s -> 32s with +/- 25% jitter, capped at 5 retries
- **Retry-After**: header (seconds or HTTP-date) is honored when present and overrides backoff
- **Test seam**: `__setSleepForTesting()` lets tests run instantly without real timers
- 6 new tests in `src/__tests__/solana-monitor.test.ts` cover 429 retry, `-32005` retry, Retry-After honoring, max-retry exhaustion, non-rate-limit pass-through, and message-based detection

## [5.2.1] - 2026-04-26
**Threat intel: Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)**

A single threat actor (claiming "TeamPCP") compromised both the Checkmarx KICS Docker images / VSCode-OpenVSX extensions and the `@bitwarden/cli` npm package on April 22, 2026, using a shared `audit[.]checkmarx[.]cx/v1/telemetry` exfiltration endpoint. Targets GitHub tokens, AWS/Azure/GCP credentials, npm tokens, SSH keys, and Claude configs. Marked as a successor to the Shai-Hulud npm worm.

- **C2 domains**: `audit[.]checkmarx[.]cx`, `checkmarx[.]cx` (`src/ioc-blocklist.ts`)
- **C2 IPs**: `94[.]154[.]172[.]43`, `91[.]195[.]240[.]123`
- **Compromised package**: `@bitwarden/cli@2026.4.0`
- **New campaign rules** in `src/patterns.ts`:
  - `CHECKMARX_SHAI_HULUD_V3` — matches the `Shai-Hulud: The Third Coming` exfil marker string
  - `CHECKMARX_MCP_ADDON` — matches the `mcpAddon.js` loader filename
  - `BITWARDEN_CLI_LOADER` — matches `bw_setup.js` / `bw1.js` loader/payload pair
- 4 new tests in `src/__tests__/campaigns.test.ts`

## [5.2.0] - 2026-04-08
**Self-Scan Clean + Text Wrapping** — the scanner no longer flags its own source code. Scanning `supply-chain-guard` itself drops from 100/critical (243 critical + 137 high) to clean.

**Scanner source exclusion** (`src/scanner.ts`):
- New shared `SCANNER_SOURCE_FILE` and `TEST_FILE_REGEX` constants replace duplicated inline regexes
- `checkIOCBlocklist()` and `checkThreatIntel()` now skip scanner definition files and test files — eliminates ~50 IOC/threat-intel self-matches
- `checkMultiLineProtestware()` skips scanner source and test files — eliminates proximity false positives

**Pattern-level guards** (`src/patterns.ts`):
- `notTestFile: true` added to all ~120 pattern rules (was only on 1). Test files with malware samples are no longer flagged
- New `SCANNER_SRC` regex excludes scanner definition files from 35 rules across CAMPAIGN_PATTERNS, INFOSTEALER_PATTERNS, SECRETS_PATTERNS, LURE_PATTERNS, BEACON_MINER_PATTERNS, and CAMPAIGN_PATTERNS_V2
- Existing `notFilePattern` regexes merged for rules that already had one (VIDAR_BROWSER_THEFT, PROXY_BACKCONNECT, DROPPER_TEMP_EXEC)

**Text wrapping** (`src/reporter.ts`):
- New `wrapText()` helper replaces `trunc()` for description, match, and fix fields in findings output
- Long text now word-wraps across multiple lines within box borders instead of being cut off with `…`

## [5.1.1] - 2026-04-07
**CI and test fixes**
- CI workflow: add GitHub Release creation step — after npm publish, automatically creates a GitHub Release with changelog notes extracted from README.md
- `reporter.test.ts`: fix 3 text-format assertions that checked old output patterns (`"scan report"`, `"52/100"`, `"None"`) broken by the v5.1.0 ASCII output redesign

## [5.1.0] - 2026-04-07
**Comprehensive ASCII CLI output** — complete redesign of the default text reporter.
- Double-line banner header (`╔╗`) with tool name and version
- Risk score with 36-char visual gauge bar, color-coded by severity level
- Findings summary as a severity histogram with proportional `█░` bars scaled to highest count
- Finding cards with structured `match` / `fix` label indenting and `···` dot-line separators
- Trust breakdown and risk dimensions with 32-char bar gauges and divider before Overall
- All sections framed in `┌─┐ / └─┘` box-drawing borders at 80-char terminal width
- Fixed stale hardcoded `4.8.0`/`4.9.0` version strings in SARIF, SBOM metadata, and HTML footer

## [5.0.1] - 2026-04-07
**False positive fixes — second pass** after live workspace testing revealed additional FPs.
- `PROXY_HANDLER_TRAP`: `notFilePattern` extended to cover non-minified vendor files in `/static/js/`, `/vendor/`, `/public/js/`, `/assets/js/` directories (e.g. `tailwindcss.js`)
- `SHAI_HULUD_WORM` / `SHAI_HULUD_CRED_STEAL`: switched from `notFilePattern(yml)` to `onlyExtensions` for source code only — eliminates FPs on `.md`, `.json`, and other doc/config files
- `README_LURE` rules: `onlyFilePattern` tightened to filename-based match (README/CHANGELOG/DESCRIPTION/CONTRIBUTING) instead of any `*.md` file — eliminates FPs on `docs/*.md`
- `DROPPER_TEMP_EXEC`: pattern tightened from `save.*\.exe` to `saveFile\(` to avoid matching variable names
- `PROTESTWARE_PROXIMITY`: destructive token detection now requires actual function calls (`fs.rm*\s*\(`) rather than any line containing `child_process`

## [5.0.0] - 2026-04-07
**Context-Aware False Positive Elimination** — workspace-wide scan of 100k+ LOC across 15 projects identified 14 systematic FP categories. v5.0.0 eliminates all of them without weakening real detection.

**New PatternEntry context fields** (`src/types.ts`):
- `onlyFilePattern?: RegExp` — only apply pattern to files whose path matches (e.g. README/docs only)
- `notFilePattern?: RegExp` — skip files whose path matches (e.g. `.min.js`, `.yml`)
- `notTestFile?: boolean` — skip test/spec/fixture/conftest files

**Rule-level fixes** (`src/patterns.ts`):
- `README_LURE_CRACK` / `README_LURE_LEAKED` / `README_LURE_URGENCY`: `onlyFilePattern` → README/CHANGELOG/`.md` files only. Source files like `.ts` no longer trigger these
- `SHAI_HULUD_WORM` / `SHAI_HULUD_CRED_STEAL`: `notFilePattern: /\.ya?ml$/` → `npm publish` in CI workflow YAML is standard; worm runs it from JS/TS code
- `PROXY_HANDLER_TRAP` / `BEACON_INTERVAL_FETCH` / `VIDAR_BROWSER_THEFT` / `PROXY_BACKCONNECT`: `notFilePattern: /\.min\.(js|css)$/` → minified files put everything on one line, making unrelated patterns appear co-located
- `DROPPER_TEMP_EXEC` / `MINER_CONFIG_KEYS`: `notFilePattern: /\.json$/` → Bootstrap icon JSON files won't trigger mining config detection
- `IAC_HARDCODED_SECRET`: `notTestFile: true` + pattern excludes dummy values (`test-key`, `your_*`, `example`, `placeholder`, `changeme`)
- `VIDAR_BROWSER_THEFT`: pattern tightened to require OS-specific browser data paths (Windows AppData, macOS Library, Linux .mozilla)
- `PROXY_BACKCONNECT`: pattern tightened to require SOCKS proxy protocol indicators or IP:port format

**Scanner fixes** (`src/scanner.ts`):
- `.claude/` directory excluded from scanning (eliminates 7× duplicate findings from Claude Code worktrees)
- `CRITICAL_FINDING_NO_OWNER` and `RISK_STAGNATION_HIGH` excluded from risk score calculation (meta-governance findings caused circular score inflation)
- `relativePath` normalized to forward slashes — cross-platform consistency in all finding `file` fields
- `checkBeaconMinerPatterns` now respects `notFilePattern`/`onlyFilePattern`/`notTestFile` like `checkFilePatterns`
- Binary detection path splitting fixed for cross-platform compatibility

**Continuous monitor fix** (`src/continuous-monitor.ts`):
- `RISK_STAGNATION_HIGH` requires ≥5 history entries before firing (avoids false alarms on new projects)

**SCANNABLE_EXTENSIONS**: `.md` added — README/CHANGELOG files now scanned for lure patterns via `checkFilePatterns`

- 22 new context-aware tests (629 total)
- Expected score reduction: projects scoring 100/critical due to FPs → ≤20/low with no actual malware

## [4.9.0] - 2026-04-07
- **New: SBOM Generator** — reads `package-lock.json` (v2+) to generate CycloneDX 1.6 SBOMs with real `components[]` (name, version, PURL, hashes, licenses). Falls back to `package.json` direct deps. VEX statements for suppressed findings. Use `--sbom-output <file>` to write separately.
- **New: SLSA Verifier** — detects SLSA provenance level (0–3) per project. Checks for sigstore/cosign signing, `slsa-github-generator` usage, hermetic build evidence, provenance attestation files. New rules: `SLSA_LEVEL_0`, `SLSA_NO_PROVENANCE`, `SLSA_UNSIGNED_ARTIFACTS`.
- **New: GitHub Actions PPE Patterns** — `GHA_PPE_PULL_TARGET` (critical), `GHA_SCRIPT_INJECTION` (critical), `GHA_OIDC_WRITE_PERM`, `GHA_CACHE_POISONING`, `GHA_ARTIFACT_DOWNLOAD`, `GHA_SELF_MODIFY`. Known malicious SHA blocklist (tj-actions Sep 2025, reviewdog).
- **New: Dependency Confusion Enhancements** — `DEP_HALLUCINATED_PACKAGE` (AI-hallucinated npm/PyPI names), `DEP_FRESH_PUBLISH` (version < 24h old), `DEP_SCOPED_PUBLIC` (internal-looking scoped package on public registry), `scanPypiDependencyConfusion()` for `requirements.txt`/`pyproject.toml`.
- **False Positive Reduction** — scanning a 100k+ LOC production codebase went from 819 findings/critical to 17 findings/high:
  - `LOCKFILE_ORPHANED_DEPENDENCY`: 794 individual findings → 1 aggregated summary (npm v7 flat lockfile fix)
  - `TYPOSQUAT_LEVENSHTEIN`: pre-check against popular-packages set; min name length ≥4; short popular packages (ws/pg/nx) excluded from comparison; bcryptjs/swr/tsx/zod added to whitelist
  - `SVG_SCRIPT_INJECTION`: restricted to `.svg` files only (new `onlyExtensions` field on PatternEntry)
  - `IMPORT_EXPRESSION`: backtick without `${...}` expression no longer triggers; severity high→medium
  - `BEACON_INTERVAL_FETCH`: severity high→medium (React polling false positive)
  - `DEAD_DROP_DNS_TXT` / `C2_DOH_RESOLVER`: severity high→medium (false positives in security tooling)
  - `GHA_ENV_EXFIL`: pattern tightened — only fires when secrets/env passed as curl data/header
  - `WORKFLOW_SECRET_TO_UPLOAD_PATH`: severity high→medium, confidence 0.7→0.6
  - `SECRETS_SSH_KEY_READ`: pattern requires specific key filenames (`id_rsa`, `id_ed25519` etc.) — no longer fires on `cat >> ~/.ssh/known_hosts` CI setup
- **Score Calculation**: per-rule deduplication (each unique rule contributes once to score) + weights medium 8→5, low 3→2
- 45 new tests (607 total)

## [4.8.0] - 2026-04-04
- **New: Continuous Risk Monitor** -- persistent risk history, trend detection (spikes, stagnation, increasing)
- **New: Triage Engine** -- finding ownership, status tracking, governance checks (unowned critical, expired acceptances)
- **New: SLA Engine** -- remediation deadline tracking with breach and at-risk detection
- **New: Risk Forecasting** -- linear regression-based trajectory prediction
- **New: Security Metrics** -- open critical/high, SLA compliance rate, risk trend, top contributors
- 18 new tests (562 total)

## [4.7.0] - 2026-04-04
- **New: Attack Graph Engine** -- models relationships between repos, packages, workflows, secrets, IOCs as directed graphs with exploitable attack paths
- **New: Active Validation Framework** -- confidence tiers (heuristic/correlated/validated/confirmed), rationale and evidence per finding
- **New: Workflow Modeler** -- models GitHub Actions as executable chains, detects secret-to-egress and untrusted-action-in-release paths
- **New: Secret Simulator** -- honeytoken system for sandboxed analysis (fake .npmrc, .env, SSH keys, AWS creds)
- **New: Org Posture Engine** -- portfolio-wide risk posture with systemic drift detection, recurring risky packages/actions
- **New:** `--export-graph json|mermaid` for attack graph visualization
- **New:** Mermaid diagram export for attack paths
- 19 new tests (544 total)

## [4.6.0] - 2026-04-04
- **New: Remediation Engine** -- concrete, prioritized fix steps for every finding
- **New: Fix Suggestions** -- machine-readable patches (pin actions, fix registries)
- **New: Incident Playbooks** -- full response playbooks for GlassWorm, Vidar, npm takeover, fake repos, CI/CD poisoning
- **New: SOC Exporter** -- JSON incident bundles, markdown incident reports, CSV summaries
- **New: Dependency Governance** -- untrusted source detection in lockfiles
- **New:** `--export-incident-md` for ticket-ready incident reports
- **New:** `--export-fixes` for automatable fix suggestions
- **New:** Remediation plan section in text/HTML reports
- 24 new tests (525 total)

## [4.5.0] - 2026-04-04
- **New: Threat Intelligence** -- real-time IOC feed integration with confidence scoring and decay
- **New: Adaptive Risk Engine** -- multi-dimensional scoring (code/deps/repo/CI + confidence)
- **New: Diff-Based Scanning** -- `--since <commit>` scans only changed files
- **New: Org Scanning** -- `supply-chain-guard org <github-org>` scans entire organizations
- **New:** Advanced obfuscation v2 (split strings, multi-layer encoding, runtime deobfuscation)
- **New:** Risk dimensions in text/JSON output (code risk, dep risk, CI/CD risk, threat intel)
- 19 new tests (501 total)

## [4.4.0] - 2026-04-04
- **New: Policy Engine** -- `.supply-chain-guard.yml` config for rule disable, severity overrides, allowlists, suppressions
- **New: Baseline System** -- `--save-baseline` / `--baseline` for diff-only CI scanning (only new findings)
- **New: Trust Signals** -- positive indicators (SECURITY.md, CODEOWNERS, LICENSE, lockfile, repository link)
- **New:** Secret exfiltration chain correlations (install hook + network + obfuscation)
- **New:** Suppression count in reports
- 18 new tests (482 total)

## [4.3.0] - 2026-04-04
- Documentation overhaul: complete README rewrite covering all features through v4.2
- Updated all version references, examples, and detection rule tables

## [4.2.0] - 2026-04-04
- **New: Correlation Engine** -- links findings into incident-level attack chains (15+ rules)
- **New: Trust Breakdown** -- 4-dimension scoring (publisher/code/dependency/release)
- **New: Install Hook Scanner** -- deep analysis (secret harvesting, download-exec, binary blobs)
- **New: Dependency Risk Analyzer** -- Levenshtein typosquat detection
- **New: Publishing Anomaly Detector** -- maintainer changes, version gaps
- **New: Release Scanner** -- double extensions, LNK, PE magic, password hints
- **New:** C2 patterns (DoH, Gist dead-drops, dynamic WebSocket)
- **New:** Secrets detection (AWS, GitHub, SSH, npm tokens, private keys)
- 59 new tests (464 total), ~174 detection rules

## [4.1.0] - 2026-04-04
- **New: GitHub Trust Scanner** -- repo metadata, star-farming, release artifacts, README lures
- **New: IOC Blocklist** -- known C2 domains/IPs, malware hashes, bad npm versions, malicious accounts
- **New:** Vidar/GhostSocks/dropper patterns, dead-drop resolver detection
- **New:** Claude Code leak campaign signatures, fake AI tool lure detection
- 42 new tests (405 total), ~143 detection rules

## [4.0.0] - 2026-04-04
- **New:** Dockerfile, package config, git security, Cargo/Rust, Go module, entropy scanners
- **New:** Build-tool, monorepo, IaC/Terraform patterns
- **New:** HTML report format with severity filtering
- **New:** Shai-Hulud worm, advanced obfuscation, campaign signatures
- 94 new tests (363 total), 110+ detection rules

## [3.1.0] - 2026-03-26
- SBOM export (CycloneDX 1.5), `--fail-on` flag, full test coverage (269 tests)

## [3.0.0] - 2026-03-26
- PyPI scanner, GitHub Actions scanner, SARIF output, Solana watchlist

## [2.0.0] - 2026-03-19
- Multi-platform scanner (npm, PyPI, VS Code), dependency confusion, lockfile checks

## [1.0.0] - 2026-03-19
- Initial release: GlassWorm detection, npm scanning, Solana C2 monitoring

[Unreleased]: https://github.com/homeofe/supply-chain-guard/compare/v5.17.5...HEAD
[5.17.6]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.6
[5.17.5]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.5
[5.17.4]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.4
[5.17.3]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.3
[5.17.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.2
[5.17.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.1
[5.17.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.0
[5.16.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.16.0
[5.15.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.15.0
[5.14.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.14.0
[5.13.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.13.0
[5.12.4]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.12.4
[5.12.3]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.12.3
[5.12.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.12.2
[5.12.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.12.1
[5.12.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.12.0
[5.11.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.11.1
[5.11.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.11.0
[5.10.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.10.0
[5.9.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.9.0
[5.8.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.8.0
[5.7.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.7.0
[5.6.3]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.6.3
[5.6.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.6.2
[5.6.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.6.1
[5.6.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.6.0
[5.5.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.5.0
[5.4.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.4.2
[5.4.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.4.1
[5.4.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.4.0
[5.3.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.3.0
[5.2.45]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.45
[5.2.44]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.44
[5.2.43]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.43
[5.2.42]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.42
[5.2.41]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.41
[5.2.40]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.40
[5.2.39]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.39
[5.2.38]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.38
[5.2.37]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.37
[5.2.36]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.36
[5.2.35]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.35
[5.2.34]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.34
[5.2.33]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.33
[5.2.32]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.32
[5.2.31]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.31
[5.2.30]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.30
[5.2.29]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.29
[5.2.28]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.28
[5.2.27]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.27
[5.2.26]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.26
[5.2.25]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.25
[5.2.24]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.24
[5.2.23]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.23
[5.2.22]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.22
[5.2.21]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.21
[5.2.20]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.20
[5.2.19]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.19
[5.2.18]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.18
[5.2.17]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.17
[5.2.16]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.16
[5.2.15]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.15
[5.2.14]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.14
[5.2.13]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.13
[5.2.12]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.12
[5.2.11]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.11
[5.2.10]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.10
[5.2.9]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.9
[5.2.8]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.8
[5.2.7]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.7
[5.2.6]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.6
[5.2.5]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.5
[5.2.4]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.4
[5.2.3]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.3
[5.2.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.2
[5.2.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.1
[5.2.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.2.0
[5.1.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.1.1
[5.1.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.1.0
[5.0.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.0.1
[5.0.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.0.0
[4.9.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.9.0
[4.8.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.8.0
[4.7.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.7.0
[4.6.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.6.0
[4.5.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.5.0
[4.4.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.4.0
[4.3.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.3.0
[4.2.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.2.0
[4.1.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.1.0
[4.0.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v4.0.0
[3.1.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v3.1.0
[3.0.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v3.0.0
[2.0.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v2.0.0
[1.0.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v1.0.0
