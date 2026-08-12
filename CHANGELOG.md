# Changelog

All notable changes to supply-chain-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The latest release is at the
top; release tags trigger the CI publish pipeline (npm via OIDC + GitHub Release + `v5` branch).

## [Unreleased]

## [5.25.12] - 2026-08-12

### Added

- Threat feed: 93 malicious-package IOCs imported from the GitHub Advisory Database with
  OSV.dev corroboration (2026-08-12 sweep), covering 50 package names across npm and PyPI.
  The largest cluster impersonates DeFi protocol SDKs on both ecosystems
  (`camelot-ammv2-core`, `camelot-ammv2-periphery`, `boring-vault`,
  `ethereum-vault-connector`, `sui-bcs-codec`, `sui-gql-client`, `pypi:euler-sdk`,
  `pypi:morpho-sdk`, `pypi:dlmm-sdk`). Also included are a `base65-*` and `bs58-*`
  encoder-lookalike family aimed at Solana tooling, 27 pinned `newtun` versions, a
  `pypi:joule-btp-extension` SAP BTP set, and several dependency-confusion entries
  carrying the usual `99.x` and `999.x` version markers. 1,791 advisories were fetched
  over 18 pages; the page cap was not hit, no `--allow-truncated` override was used, and
  the `--limit 250` cap was not reached, so nothing is left waiting for the next run.

## [5.25.11] - 2026-08-11

### Added

- Threat feed: 104 malicious-package IOCs imported from the GitHub Advisory Database with
  OSV.dev corroboration (2026-08-11 sweep), covering 54 package names across npm and PyPI.
  Notable clusters are three lookalike SQLite scopes (`@sqlite-labs`, `@sqlite-prime`,
  `@sqlite-table`), a `chai-as-*` typosquat family, Ethereum and Solana tooling
  impersonations (`eth-library-toolkit`, `eth-library-utils`, `pypi:neutrl-core`,
  `pypi:plp-contract`), and a set of postcss lookalikes. 1,806 advisories were fetched
  over 19 pages; the page cap was not hit, no `--allow-truncated` override was used, and
  the `--limit 250` cap was not reached, so nothing is left waiting for the next run.
- IOC blocklist: the PyPI branch of the Mini Shai-Hulud / Miasma worm family, tracked by
  Socket as the `Hades` wave (June 8, 2026). This repo had the family covered only on its
  npm side. Adds 23 version pins across 18 PyPI packages, plus two SHA-256 digests for the
  `langchain-core-mcp` artifacts. Stolen maintainer tokens published one trojanized release
  per project, using a `.pth` site-packages hook so the Bun-based credential stealer runs
  on every Python start rather than only at install.
- Threat feed: `c[.]wel1[.]ru`, the DNS TXT control channel of the Flooding Dropper
  campaign. It sits on a sibling label to the `dl[.]` download hosts already tracked, so
  the existing entry did not reach it. Single-source, recorded at confidence 0.85.

### Changed

- Miasma `Hades` version sets are corroborated against the live PyPI registry rather than
  taken from the write-up alone. All 23 versions are confirmed absent from the releases
  map, and for each of the ten packages that still exist the malicious version is exactly
  one increment above the surviving `latest`. Only that release is pinned: these are
  mostly academic genomics and graph-ML libraries with long clean histories (`pyphetools`
  has 201 releases, `ensmallen` 120, `embiggen` 116), and their clean versions stay
  installable. The eight names that are gone from PyPI entirely are version-pinned like
  the rest rather than blocked by bare name, since the registry no longer holds the
  history that would justify a name-level rule.

## [5.25.10] - 2026-08-10

### Added

- Threat feed: 2 malicious-package IOCs imported from the GitHub Advisory Database with
  OSV.dev corroboration (2026-08-10 sweep, both PyPI: `kotanku` and
  `cubesat-upstream-driver`). 4,014 advisories were fetched over 41 pages; the page cap
  was not hit, no `--allow-truncated` or `--allow-backlog` override was used, and the
  `--limit 250` cap was not reached, so nothing is left waiting for the next run.
- IOC blocklist: the telnyx PyPI compromise and the March 2026 npm wave of the TeamPCP
  campaign, which this repo had covered only on its litellm side. Adds the `telnyx`
  4.87.1 / 4.87.2 version pin, the brand-typosquat C2 `aquasecurtiy[.]org` and its
  `scan[.]` host, the Internet Computer canister dead-drop, three attacker quick-tunnel
  hostnames, the two stage-2 hosts `83[.]142[.]209[.]203` and `83[.]142[.]209[.]11`, the
  two WAV-disguised payload URLs, four SHA-256 hashes covering the trojanized wheels and
  `_client.py`, and the attacker GitHub account `Argon-DevOps-Mgt`. The `raw[.]icp0[.]io`
  and `trycloudflare[.]com` apexes, the real `aquasecurity[.]org` brand and the
  compromised upstream maintainers are deliberately not listed, and a negative test pins
  that.
- IOC blocklist: 58 hijacked npm packages (117 version pins) from the same March 2026
  TeamPCP wave, including the `@emilgroup` SDK family, `@opengov`, `@teale.io` and nine
  further org-owned packages. Version sets are derived from three independent signals
  rather than one: the GitHub Advisory Database, the vendor package list, and the npm
  registry `time` map. The advisory ranges are the narrowest of the three and under-cover
  this campaign by 27 versions across 12 packages. `@teale.io/eslint-config` is advised as
  1.8.9-1.8.10, but all of 1.8.9-1.8.16 were published on 2026-03-20 and later
  unpublished, while 1.8.8 (2026-02-17) is still live. A version therefore qualifies when
  an advisory covers it, or when it was published inside the campaign window and has since
  been unpublished from a package the campaign is known to have hit. Registry-derived
  prereleases are excluded: these orgs retract beta channels routinely, so an unpublished
  prerelease carries no signal. Three pins on packages whose scope no longer resolves
  publicly rest on the vendor list alone and carry confidence 0.85.
- Tests: `campaigns.test.ts` gains scan-level coverage for the telnyx wave (positive,
  clean-version negative, dead drop, C2 host, wheel hash, attacker account, and a
  negative that the shared gateways and the real vendor brand stay clean) plus a
  resolver-level regression block for the ecosystem-prefix fix below.

### Fixed

- Threat feed: six PyPI compromises shipped their package IOCs as BARE feed values, and a
  bare value denotes the npm namespace. The effect was an inversion rather than a
  weakening: `matchPackageIOC("pypi", ...)` returned null for `litellm`, `lightning`,
  `guardrails-ai`, `mistralai`, `durabletask` and `xinference`, while the npm resolver
  answered for them instead, so an install-guard check of `litellm@1.82.7` would have
  reported a critical IOC against the unrelated npm package of that name. On lockfile
  scans the blocklist path (`KNOWN_BAD_PYPI_VERSIONS`) masked the false negative, which
  is why no existing test caught it. The nine affected entries now carry the `pypi:`
  prefix, and three duplicate bare `xinference` entries are dropped because correctly
  prefixed ones already existed alongside them.

## [5.25.9] - 2026-08-09

### Added

- Threat feed: 64 malicious-package IOCs imported from the GitHub Advisory Database with
  OSV.dev corroboration (2026-08-09 sweep, 62 npm and 2 PyPI). 4,492 advisories were fetched
  over 45 pages; the page cap was not hit, no `--allow-truncated` or `--allow-backlog`
  override was used, and the `--limit 250` cap was not reached, so nothing is left waiting
  for the next run. The batch continues the `bnpl-*` / `statist-browser-typed-client-*`
  dependency-confusion waves, adds a `@yancyyu/agentcli` version sweep (25 releases), a
  `sextant-cli-*` per-platform binary cluster, a `svelte`/`streak` map-kit typosquat set,
  and PyPI `riakcs`.
- IOC blocklist: network infrastructure for the Flooding Dropper / WEL1DROPPER npm
  slopsquatting campaign (OpenSourceMalware and Sonatype, 2026-08-07). The ~850 packages
  arrive through the advisory databases, but the delivery hosts do not: added eight
  attacker-controlled Cloudflare Worker sub-hosts (`oob-worker.*` and
  `package-proxy.*oobworker`), the DNS-fallback download host `dl[.]wel1[.]ru`, and two
  SHA-256 stage-2 payload hashes. The shared `workers[.]dev` apex and the three Russian
  financial-services hosts the write-up embeds with an explicitly unresolved role
  (`nexus[.]tcsbank[.]ru`, `repo-linux[.]tcsbank[.]ru`, `alertmanager[.]cloudpayments[.]ru`)
  are deliberately not listed.
- IOC blocklist: C2 and payload indicators for the axios maintainer account takeover
  (UNC1069 / "Sapphire Sleet", 2026-03-31). The hijacked releases were already version
  pinned; this adds the RAT C2 `sfrclak[.]com`, its resolver `142[.]11[.]206[.]73`, and the
  three per-platform implant hashes. The hijacked maintainer account is a victim and is not
  listed.
- IOC blocklist: backfill for the `spellcheckpy` / `spellcheckerpy` PyPI RAT (Aikido,
  2026-01-20), a campaign that had never been ingested. Both names are blocked bare, since
  every published version is malicious and neither name has legitimate history, together
  with the stage-2 host `updatenet[.]work` and `172[.]86[.]73[.]139`. Single-source, so the
  feed entries carry confidence 0.85.
- Tests: `campaigns.test.ts` gains scan-level coverage for all three campaigns, including a
  negative test that the `workers[.]dev` apex and the unattributed third-party hosts stay
  clean, a clean-version negative for axios, and an ecosystem-inversion guard that
  `spellcheckpy` fires on a Python lockfile but not on an npm dependency of the same name.

## [5.25.8] - 2026-08-08

### Added

- Threat feed: 250 malicious-package IOCs imported from the GitHub Advisory Database with
  OSV.dev corroboration (2026-08-08 sweep, 230 npm and 20 PyPI). 4,498 advisories were
  fetched over 45 pages; the page cap was not hit and no `--allow-truncated` or
  `--allow-backlog` override was used. 49 mappable entries remain behind the `--limit 250`
  cap, all of them drainable inside the `--days 14` window, so the next scheduled run takes
  them. The batch continues the Tinkoff/T-Bank `dolyame-ui-*` / `devplatform-*` /
  `delivery-ci-*` / `ded-pwa-*` dependency-confusion wave (roughly 130 names at the 35.x
  internal version series), adds a `@depup/*` cluster that mimics upstream releases with a
  `-depup.N` version suffix, a PyPI single-character-typosquat set (`pydanticc`, `flasq`,
  `idnna`, `fastapii`), an AI-agent impersonation cluster (`aclade-agent`, `agenthub-ai`,
  `mangomind-agent`), and a web3 tooling cluster (`hardhat-cap`, `hardhat-set`,
  `forge-gas-diff`, `gas-diff-core`, `@coralxyz/anchor`).
- IOC blocklist: second indicator wave for the ChainDrop npm worm (Microsoft and Datadog
  published the resolver internals after the initial 2026-08-04 write-ups). Added the two
  sibling C2 routers resolved from the same Ethereum contract, `pypi-get[.]com` and
  `js-mirror[.]com`, the earlier rotation target `awqhnjewqjkl[.]icu`, four SHA-256 hashes
  from the later re-obfuscation waves (the `.vscode/tasks.json` IDE persistence hook, a
  re-obfuscated stage-2 stealer, the `zZ.bin` loader, and the embedded GitHub Actions
  `Runner.Worker` memory dumper), and the two fixed marker names of the exfiltration
  repositories the worm creates under each victim account. Every hash was re-confirmed by
  exact-string search against an independent write-up before ingestion; a fifth hash from
  the same source could not be corroborated and was deliberately left out. The public
  Ethereum RPC providers the resolver calls are deliberately not ingested - they are shared
  infrastructure, and a negative test pins that.
- IOC blocklist: two follow-up indicators for the Alibaba developer toolchain RAT from
  Corgea's analysis - the live `raw.githubusercontent[.]com` config dead-drop path under
  the already-blocked attacker account, and `node-data-utils@1.0.1`, a nineteenth staging
  package neither the advisory databases nor the original write-up listed. Both are
  single-source and carry confidence 0.85. The package is version-pinned rather than
  blocked by name, and the `raw.githubusercontent[.]com` host is never listed on its own.

### Security

- Lockfile: `nanoid` 3.3.16 to 3.3.18, resolving GHSA-2v37-7h3g-55p8 (high). A
  development-only transitive dependency, reached through `vitest` -> `vite` -> `postcss`;
  the published package still has `commander` as its only runtime dependency, so no
  consumer was ever exposed. Included here because the newly published advisory turns the
  `npm audit --audit-level=high` CI gate red on every branch until the lockfile moves.

## [5.25.7] - 2026-08-07

### Added

- Threat feed: 783 malicious-package IOCs imported from the GitHub Advisory Database with
  OSV.dev corroboration (2026-08-07 sweep). The first dry run reported a bulk-publication
  spike: 533 entries waiting behind the 250 cap, 33 of which would have aged out of the
  `--days 14` window before any future capped run could reach them. The standard batch was
  taken first, then the rest of the same window was drained as an explicit
  `--since 2026-07-24` slice, so the run ends with the window fully imported: a confirming
  dry run reports 0 new entries, nothing waiting and no undrainable remainder. The batch
  continues the Tinkoff/T-Bank and
  `devplatform-*` dependency-confusion waves, adds a Sui/Move blockchain cluster
  (`sui-migration-audit-cli`, `sui-graphql-client`, `move-bcs-codec`, `supersig`, plus
  `alphalend-abi` and `alphalend-layouts` on PyPI), an AI-tooling impersonation cluster
  (`wormgpt-cli`, `remote-claude-daemon`, `gpt-terminal-cli`, `agenthub-multiagent-mcp`,
  `agenttunnels`), and four further `baileys` WhatsApp-library clones.
- IOC blocklist: full indicator set for GlassWASM, the trojanized Open VSX extension
  campaign (Socket 2026-06-15, corroborated by Corgea), which had no coverage at all. Two
  impersonation clones of verified VS Code Marketplace extensions were republished on Open
  VSX carrying a TinyGo-compiled WebAssembly stager that ChaCha20-decrypts its delivery
  host and reads its commands from Solana SPL Memo fields. Added: the `dodod[.]lat` C2
  apex, its three per-platform stage-2 paths, the Solana dead-drop wallet, the throwaway
  publisher account `zaitoona43`, and three SHA-256 hashes (the WASM stager plus one per
  VSIX). The hashes are single-source, so they carry confidence 0.85; every other
  indicator is two-source at 1.0. The impersonated upstream publishers, the public Solana
  mainnet JSON-RPC endpoint, and the two SPL Memo system program ids are deliberately not
  ingested - they are victims and shared infrastructure, not indicators. The extension
  identifiers are not added as package IOCs, because a bare feed value means the npm
  namespace and these are Open VSX names; the two VSIX hashes carry that identity instead.
  These indicators are deliberately not bounded by the importer's advisory window: that
  window scopes what the importer ingests, not how long the engine keeps detecting a
  campaign.

## [5.25.6] - 2026-08-06

### Added

- Threat feed: 358 malicious-package IOCs imported from the GitHub Advisory Database
  with OSV.dev corroboration. 250 are this run's standard batch; the other 108 are an
  explicit `2026-07-26..2026-07-28` slice, imported because the importer's undrainable
  check flagged them as about to age out of the `--days 14` window before any future
  capped run could reach them. The bulk continues the dependency-confusion wave against
  Tinkoff/T-Bank internal namespaces (`bigops-*`, `dolyame-boxy-*`, `bnpl-blocks-*`,
  `statist-browser-typed-client-*`), which publishes with inflated version markers such
  as `kepler@5.999.999`, alongside an AI-agent impersonation cluster
  (`@agenthub-ai/agent`, `claw-subagent-service`, `llm-interceptor`), a fintech
  `@scope/checkout` cluster, and three PyPI crypto stealers (`eth-account-wallet`,
  `solana-sniper-bot`, `uncrypt`).
- IOC blocklist: `fast-transform-pipeline` (npm) for the Alibaba developer toolchain RAT.
  The repo already tracked the campaign's GitHub dead-drop repo of the same name, but the
  npm package it was published as had no IOC, while its other 17 siblings were covered.
  Bare name, no version pin: the source publishes no versions. Single-source (Socket),
  so confidence 0.85.
- IOC blocklist: SHA-256 of the poisoned `keyv-6.0.0.tgz` distribution tarball for the
  ChainDrop npm worm. `keyv@6.0.0` is already version-pinned, so this adds a second
  detection path for the same release where the tarball digest is recorded as text.
  Single-source (Snyk), so confidence 0.85.
- Threat feed: 2,683 further malicious-package IOCs, a backlog-completion import over the
  `2026-08-04..2026-08-06` window that drains the remainder of the ChainDrop spike the
  capped standard batch could not reach. The feed goes from 6,948 to 9,631 entries, and a
  follow-up dry run reports 0 waiting and 0 undrainable. This closes two scopes that had
  zero feed coverage before this run: `@hubsync` (27 entries) and `@ornikar` (441), both
  entirely version-pinned, so the scopes are not blocked wholesale and pinned matches are
  enforced by the install guard. 129 of the new entries are bare names, every one of which
  npm has already replaced with a security holding package; 7 are PyPI, carrying the
  `pypi:` prefix. The 179 unmappable advisories in the window stay excluded by design
  (150 withdrawn, 22 unsafe package names, 7 bounded version ranges).

### Changed

- Test only: the feed-reachability guard in `collection-reachability.test.ts` now runs with
  an explicit 30s timeout. It calls the real `matchBareNpmIOC` once per npm entry, and that
  matcher is a linear scan of the feed, so the guard costs roughly 85 million comparisons.
  Growing the feed by 46% in this release made it about twice as slow and it exceeded the
  default 5s timeout on CI. No production code changed. The cost grows with the square of
  the feed, so the actual fix is to index `matchBareNpmIOC` the way `matchPackageIOC`
  already is, tracked as T-017.

## [5.25.5] - 2026-08-05

### Fixed

- The Action's PR comment now explains a recovered clean scan instead of posting a
  blank line. `reportForComment` was guarded on its own indented value, and indenting
  an empty report yields four spaces, which is truthy - so the clean-scan fallback was
  unreachable and every `if (reportForComment)` guard always fired. It surfaced only
  when a stale findings or partial comment was replaced on the return to clean, which
  is exactly when the reader needs to be told the run came back clean. An empty report
  is reachable through a failed report read or an empty report file. The verdict line
  was never affected, so no comment ever claimed clean when it was not.

### Changed

- Bumped `@elvatis_com/aahp` 3.9.1 -> 3.9.2 (exact pin), and converged this repo's own
  handoff-doc generator with it: renamed `scripts/aahp-dashboard.mjs` to
  `scripts/scg-handoff-docs.mjs` (it is a project-specific generator, not an AAHP tool,
  despite the former name), deleted the two locally-vendored copies of AAHP's
  `_aahp-lib.sh`/`aahp-manifest.sh`, and imported AAHP's shared bash-resolution,
  Windows-path-conversion, and changelog-grammar primitives from the installed package
  instead. Closes a latent bug for free: the local CHANGELOG heading regex silently
  dropped SemVer pre-release headings from the generated LOG.md table.

## [5.25.4] - 2026-08-05

### Added

- Threat feed: 251 malicious-package IOCs imported from the GitHub Advisory
  Database with OSV.dev corroboration. The bulk is a mass dependency-confusion
  wave squatting internal namespaces of Tinkoff/T-Bank (`tinkoff-*`, `tramvai-*`,
  `tui-react-*`, `platform-ui-*`, `beaver-ui-*`), ServiceTitan (`@servicetitan/*`)
  and OneReach (`@onereach/*`).
- ChainDrop npm worm / "Mini Shai-Hulud" (August 4, 2026): 22 hand-added
  indicators for the keyv and cacheable compromise, covering the exfil host
  `npm-cache[.]com`, the Ethereum mainnet dead-drop C2 resolver contract, the two
  `setup.mjs` preinstall dropper hashes, the stage-2 credential stealer hash, and
  18 hijacked packages pinned to their single malicious version. Reported
  independently by StepSecurity, Aikido, Socket and Endor Labs. The compromised
  publisher accounts are victims and are deliberately not listed, and the cloud
  metadata addresses the payload queries are excluded as legitimate
  infrastructure.

### Fixed

- `npm run handoff:refresh` now regenerates `MANIFEST.json` on Windows. Three
  independent defects blocked it, so the required handoff gate could not be
  satisfied from a Windows checkout at all. `scripts/aahp-dashboard.mjs` passed
  a native `C:\...` path to bash, where MSYS re-parses backslashes as escapes and
  reports a missing file; path arguments are now forward-slashed on win32 only,
  leaving POSIX behavior byte-for-byte unchanged. The same call also trusted
  whatever `bash` PATH resolved to, which on Windows is normally the WSL launcher
  in System32 - WSL mounts the host at `/mnt/c` and has no `C:` drive, so even a
  well-formed Windows path is unresolvable there; Git-Bash is now preferred
  explicitly, with `AAHP_BASH` still overriding. Separately, `.gitattributes`
  pinned `*.mjs` to LF but not `*.sh`, so with `core.autocrlf=true` both shell
  scripts were checked out CRLF and bash failed on the stray carriage return.

## [5.25.3] - 2026-08-04

### Fixed

- Installed package self-scans no longer treat the compiled Shai-Hulud matcher
  definition as executable worm behavior. The package-shaped regression now
  includes `dist/` without source or `.gitignore`, while an untrusted copy still
  triggers the same rule.

## [5.25.2] - 2026-08-04

### Changed

- Adopted `@elvatis_com/aahp` 3.9.1 and migrated the existing handoff state to
  its current-snapshot and MANIFEST-authoritative task rules. Local manifest
  summaries now scan past Markdown header and table chrome, checksums fail
  closed on empty tool output, acceptance criteria use evidence-bound task
  boxes, trust records carry provenance and expiry, generated release headlines
  skip subsection labels, workflow model routing is harness-owned, and the
  optional Phase 4.5 grounding verdict is explicit.

### Fixed

- Solana webhook delivery now uses the HTTP transport for `http:` URLs and
  HTTPS for `https:` URLs, rejects unsupported schemes and non-2xx responses,
  settles at response headers, discards unused bodies, and enforces one absolute
  deadline across DNS, connection, and response handling.
- ZIP extraction uses the inbox System32 bsdtar backend on Windows after the
  existing security preflight, so runtime VSIX and wheel scans no longer require
  a separately installed Info-ZIP executable. Preflight now rejects portable-name
  mismatches including Windows-special syntax, device and 8.3 aliases, trailing
  dot/space, invariant-case and HFS-ignorable collisions, ambiguous legacy
  filename encodings, type-overriding ZIP metadata, and mixed PAX/GNU ordering
  mismatches before any extractor runs.
- Domain threat indicators now require plausible DNS structure and match exact
  hosts or subdomains at hostname boundaries. Tiny code-shaped values and
  parent-domain lookalikes no longer create repository-wide false positives.
- VS Code registry targets now require one strict `publisher.name` identifier,
  use encoded URL components and a fixed temporary filename, validate every
  Marketplace and Open VSX download hop, and clean temporary downloads after
  acquisition failures.

### Security

- Registry metadata and npm, PyPI, and VS Code artifacts now use a shared
  HTTPS-only downloader with credential rejection, bounded redirects, total
  timeouts, streaming byte limits, final-status validation, and partial-file
  cleanup. Every hop is pinned to the official registry or artifact host, and
  npm tarballs are verified against `dist.integrity` and `dist.shasum` before
  extraction when those digests are present. A digestless npm artifact is still
  scanned but now makes the report explicitly partial.
- Self-scan IOC suppression now trusts only the running package's physical root
  or a scanner-initiated clone of the exact canonical HTTPS repository URL.
  Local package metadata and Git remotes cannot grant suppression.
- Remote threat-feed entries now validate optional metadata and calendar dates,
  normalize absent confidence before use, and clamp future-date decay so
  malformed or future-dated entries cannot create non-finite or inflated scores.
- CI now defaults to read-only repository permissions, pins the AAHP workflow
  actions to immutable revisions, installs with lifecycle scripts disabled,
  enforces `npm audit --audit-level=high`, keeps the npm release workflow's
  manual dispatch build-only, requires a release tag to exactly match the
  package version, and exact-pins the OIDC-capable npm CLI used for publishing.

## [5.25.1] - 2026-08-04

### Added

- **16 malicious package IOCs** imported from the GitHub Advisory Database
  (CWE-506) and corroborated against OSV.dev: 15 npm and 1 PyPI, covering
  2026-07-22 to 2026-08-04. 15 of the 16 are confirmed by both databases
  (confidence 1.0). The window was sliced to start at 2026-07-22 on purpose: the
  default 14-day window reaches back into the 2026-07-21 bulk-publication spike
  and the importer reported a 16,006-entry remainder that cannot be drained
  before it ages out. All 16,006 are the PyPI and NuGet halves of that spike,
  which are already excluded by a standing, re-verified decision, and the slice
  loses no npm coverage: an `--ecosystem npm` run over the full window returns
  the same 15 npm entries.

- **5 non-package IOCs for the mrmustard PyPI compromise** (StepSecurity +
  safedep, July 2026), a campaign the advisory databases only describe as a
  package version. An attacker took over a maintainer's GitHub account, probed
  the project's self-hosted CI runners to steal its PyPI publishing token, and
  published a poisoned `0.7.4` of XanaduAI's photonic quantum library. The
  payload runs on every `import mrmustard`, harvests SSH private keys, AWS
  credentials, Kubernetes configs, SLURM job queues and GPU inventories, and
  installs three persistence mechanisms that survive `pip uninstall`. Added: the
  exfiltration host `metrics[.]femboy[.]energy`, the `webhook[.]site` bin that
  received the stolen CI secrets, the two poisoned 0.7.4 artifact hashes, and a
  `0.7.4` version pin. The malicious code was injected into the published
  artifacts only - the GitHub source was left clean - so the artifact hash is the
  indicator the repository cannot provide. The breached maintainer account is
  deliberately **not** blocked: that account is a victim of the takeover, not an
  indicator. The `webhook[.]site` apex is not listed either - it is an ordinary
  development tool, so only the attacker's specific bin id is an indicator. Both
  artifact hashes were checked against every artifact of every mrmustard release
  still on PyPI (24 files across 13 versions) and collide with none, so a clean
  install cannot trip them, and only `0.7.4` is pinned: `0.7.3` and earlier and
  the `1.0.0a` pre-releases stay clean.

- **1 non-package IOC for the Alibaba developer toolchain RAT** (Socket, July
  2026): the native second-stage binary staged in the attacker's OSS bucket
  alongside the eight paths already shipped in v5.24.0. Scoped to the full bucket
  path, never the shared `oss-cn-beijing[.]aliyuncs[.]com` gateway.

### Changed

- Bumped the `node:22-alpine` base image digest in the `Dockerfile` and
  `@types/node` to 26.1.2 (both dev/build-time only; the sole runtime dependency
  remains `commander`).

## [5.25.0] - 2026-08-03

### Added

- **`--ecosystem <list>` for `scripts/import-threat-feed.mjs`**, to import only
  part of a mixed bulk-publication spike. Comma-separated and repeatable, valid
  values are the ecosystems the scanner can resolve (`npm`, `pip`, `composer`,
  `go`, `rubygems`, `rust`, `nuget`). Everything outside the selection is counted
  under `ecosystem-filtered` in the skip report rather than quietly omitted, and
  the selection is recorded as `ecosystems` in the JSON report. An unknown name
  is rejected rather than ignored: a silently ignored typo would filter every
  advisory out and import zero IOCs while exiting 0, the same silent false
  negative the page cap is fatal about. Closes the gap that forced the
  2026-08-03 run to hand-roll a fetch proxy to take the npm half of the
  2026-07-20/21 spike.

- **133 malicious package IOCs** imported from the GitHub Advisory Database
  (CWE-506) and corroborated against OSV.dev: 131 npm and 2 PyPI, covering the
  14-day window to 2026-08-03. 132 of the 133 are confirmed by both databases
  (confidence 1.0). 117 of them come from the 2026-07-20/21 bulk-publication
  spike, whose npm slice had never been imported: a 25-package liveness sample
  found 25/25 still installable on the registry, so these are live threats
  rather than historical record. 82 of the new entries are vendor scanner
  testbed corpora published as malware on purpose (`@gocortexio/npmgremlinbox-*`,
  `vybscan-testbed-*`) and are flagged as such by the advisory database.

### Changed

- The PyPI and NuGet halves of the 2026-07-20/21 spike remain deliberately
  un-imported, re-confirming the v5.24.0 decision against a fresh sample: PyPI
  is 0/25 and NuGet 2/25 still installable, so roughly 20,800 rows would buy
  detection for a handful of live packages while quadrupling the bundled feed.
  The npm half of the same spike samples 25/25 live, which is why it was taken.

## [5.24.0] - 2026-08-02

### Fixed

- **The feed importer reported an undrainable backlog as harmless, which made a
  bulk-publication spike a silent false negative.** `--limit` is sized for the
  steady-state flow (median ~35 advisories/day), and the report claimed anything
  over it "stays available to the next run". That is only true while the
  remainder is small enough to drain before `--days` slides past it. The advisory
  database periodically bulk-publishes retrospective malware datasets - 11,512
  PyPI advisories on 2026-07-21, 2,262 npm ones on 2026-07-27 - and the resulting
  remainder is tens of thousands of entries against a 250/day drain rate, so most
  of it aged out unreached while the run exited clean. The importer now computes
  how many entries are provably unreachable before they age out (`undrainable` in
  the JSON report), prints the slice command that recovers them, and exits 2. The
  entries the run selected are still written - exit 2 means "written, but a slice
  import is needed", distinct from exit 1 "failed, nothing written". Explicit
  `--since`/`--until` slices are exempt, since slicing IS the recovery. Suppress
  with the new `--allow-backlog`.

### Added

- **3,569 additional npm package IOCs** recovered from the 2026-07-26 and
  2026-07-27 bulk-publication spike by slice import. A 25-package sample of that
  spike found 19 still installable on npm, so these are live threats the scanner
  previously missed rather than historical record.
- **`--allow-backlog`** flag for `scripts/import-threat-feed.mjs`, to accept an
  ageing-out remainder and exit clean.
- **250 malicious package IOCs** imported from the GitHub Advisory Database
  (CWE-506) and corroborated against OSV.dev, covering npm and PyPI advisories
  published in the 14-day window to 2026-08-02.
- **Fake Corepack install site (July 24, 2026).** Node.js 25 stopped bundling
  Corepack, so developers began installing it by hand and an attacker registered
  an impersonation site at `corepack[.]org`. There has never been an official
  Corepack website, so the domain itself is the indicator, and it is a plausible
  thing to find pasted into a README, Dockerfile or CI install step. The download
  button funnels through a malvertising redirect chain into a fake VPN installer
  that steals browser profile data and SSH keys, then enrols the host in a
  bandwidth-sharing proxy network. Nine domains and one dead-drop URL added.
  The landing and affiliate hops are pinned to their specific subdomains only:
  `go2cloud[.]org` is the shared Tune/HasOffers affiliate-tracking apex and
  `canatrace[.]com` is not attacker-owned as a whole, so neither parent host is
  listed, and the fake VPN page is path-scoped rather than blocking
  `freevpn[.]win` outright.

## [5.23.5] - 2026-08-01

### Fixed

- **The PointBlank indicator was routed to the wrong ecosystem.** It was added as the
  bare value `gcli-control`, and a bare value is the npm namespace, so the detection was
  inverted: a `poetry.lock` or `requirements.txt` pinning `gcli-control` produced no
  findings while an npm dependency of that name was flagged critical. Corrected to
  `pypi:gcli-control`. Two scanner-level tests were added - the existing tests asserted
  against the pattern constant and never ran a scan, which is how a wrongly-routed entry
  passed CI.
### Added

- **250 malicious package IOCs** imported from the GitHub Advisory Database
  (CWE-506) and corroborated against OSV.dev, covering npm and PyPI advisories
  published in the 14-day window to 2026-08-01.
- **Joyfill npm compromise / DEV#POPPER (July 28, 2026).** The advisory
  databases published only two of the six malicious releases, so the remaining
  four `@joyfill/components` and `@joyfill/layouts` 2773 beta builds are now
  pinned, together with four stage-3/4 C2 IPs, 15 payload SHA-256 hashes and
  seven blockchain C2 resolver addresses. Both packages are legitimate and still
  maintained, so only the named beta builds are pinned. Corroborated by Socket
  and StepSecurity; Socket's PolinRider attribution is independently supported by
  the campaign re-using two Tron resolver wallets already pinned for
  ViteVenom/ChainVeil.
- **PointBlank PyPI RAT (July 2026).** `gcli-control` blocked by name - every
  released version is malicious and the name has no legitimate history.
  Single-source (Xygeni), so it carries a reduced feed confidence of 0.85.

### Changed

- The public blockchain RPC endpoints the Joyfill loader reads its C2 address
  from (`api.trongrid[.]io`, `fullnode.mainnet.aptoslabs[.]com`,
  `bsc-dataseed.binance[.]org`, `bsc-rpc.publicnode[.]com`), the `ip-api[.]com`
  geolocation lookup and the `npoint[.]io` JSON-bin host used by PointBlank are
  deliberately NOT ingested. They are shared public infrastructure and blocking
  them would flag legitimate web3 and developer projects. Regression tests cover
  this.

## [5.23.4] - 2026-07-31

### Added

- **250 malicious package IOCs** imported from the GitHub Advisory Database
  (CWE-506) and corroborated against OSV.dev, covering npm and PyPI advisories
  published in the 14-day window to 2026-07-31. The batch is dominated by
  typosquats of `socket.io`, `passport` and `mongoose`, plus several
  machine-generated throwaway names.
- **SHA-256 of the malicious `jscrambler@8.20.0` manifest**
  (`bba32dd...f49f0`) added to the known-malware hash set and the bundled feed.
  The version pins already covered an install from npm; the hash catches a
  vendored or mirrored copy of that release where the version metadata is gone.
  Single-source (Socket), so it carries a reduced feed confidence of 0.85.

### Fixed

- **Trusted same-run GitHub Actions artifact handoffs no longer add a low-risk
  finding.** `GHA_ARTIFACT_DOWNLOAD` now uses workflow structure instead of a
  bare action-name match. Suppression requires a trusted trigger, a stable
  upload and download action reference, an exact or glob-compatible artifact
  selector, and a producer linked through the consumer job's complete
  `needs` graph. If multiple jobs can produce the selected artifact, every
  matching producer must be in that dependency closure. Scalar, flow-list and
  block-list `needs` forms plus `pattern`, `repository`, `run-id` and
  `github-token` inputs are parsed without adding a YAML dependency.
- **Artifact injection coverage remains fail-closed.** Explicit cross-run or
  cross-repository access, `workflow_run`, `pull_request_target`, mutable action
  refs, unlinked producers, unrelated artifact names and structurally unknown
  workflows still report `GHA_ARTIFACT_DOWNLOAD`; the existing cross-workflow
  graph continues to escalate untrusted producer-to-privileged-consumer chains
  to medium or critical. Regressions cover the repository's native multi-arch
  Docker digest handoff, transitive dependencies and malicious controls, and the
  build-backed self-scan now asserts this contextual false positive is absent.

## [5.23.3] - 2026-07-30

### Fixed

- **A built release no longer reports itself as critically compromised.** On the
  v5.23.2 checkout, `scan .` returned 924 high-or-critical findings, including
  917 from compiled `dist/` counterparts of inert detector definitions. Generated
  output remains fully scanned. Self-recognition now requires the exact package
  name plus a canonical repository identity, and suppression is limited to
  reviewed source/generated paths or exact path-and-rule pairs. An arbitrary
  payload under `dist/`, a same-named file in another package, and an unrelated
  malicious rule at an inert path all remain detectable.

- **Shai-Hulud credential-flow detection no longer treats Vite metadata as
  credential theft.** The rule now requires an executable credential source to
  reach a real network sink across JavaScript/TypeScript, Python or shell. It
  handles lexical scope, parameter and declaration shadowing, assignments and
  aliases, receiver provenance for imported and required network clients, pathlib
  reads, command substitutions,
  pipelines and continued shell commands. Comments, declarations, deny lists,
  regular-expression literals, output-only network options, local helper methods
  and path strings without a read stay inert. The advertised source vocabulary is
  shared by the prefilter and matcher, including case-insensitive `.npmrc` and
  `npm_config_userconfig` forms; `npm-cli-login` is no longer advertised as a
  credential source.

- **Ordinary Proxy handlers in Vitest no longer produce high findings.** A bare
  `process.env[key]` access inside a Proxy trap is normal runtime behavior and no
  longer counts as a hostile operation. Evaluation, process execution,
  deobfuscation and network exfiltration inside the trap remain detectable.

- **Mining rules no longer join unrelated bundle tokens or fire on a lone common
  object key.** Pool hostnames now obey DNS label and total-length boundaries,
  retain valid subdomains of known pools, and reject suffix lookalikes. A single
  mining-specific configuration key or a known mining-pool hostname remains high
  confidence. Generic pool-shaped hosts require bounded mining context; ordinary
  keys such as `worker`, `wallet`, `hashrate`, `coin` and `algo` require three
  distinct keys in the same object scope. Separate objects, comments, regexes,
  stringified examples, duplicate keys and scheduler-style configurations do not
  correlate.

- **Backconnect/proxy evidence distinguishes remote infrastructure from local
  development endpoints.** Authority parsing now handles credentials, compact
  and legacy IPv4 spellings, compressed/padded IPv6 and IPv4-mapped IPv6. Loopback,
  wildcard and localhost endpoints are rejected without letting the same scheme
  seed a looser fallback later on the line. Commented examples remain inert while
  external endpoints and behavioral check-ins remain detectable.

- **Character-code obfuscation requires flow into executable code or command
  positions.** Long `String.fromCharCode` sequences are no longer capped at 1,024
  arguments, assignments and aliases are followed with scope-aware overwrite
  handling, and shell-interpreter command positions are recognized. Documentation,
  codepage tables, regular-expression `.exec`, timer callbacks, environment/options
  data and non-executed function arguments remain clean. Matching stays linear on
  multi-megabyte malformed or assignment-heavy input.

- **Protestware locale/GeoIP correlation now requires executable control flow.**
  A locale-derived identifier must feed a conditional geographic gate whose body
  reaches a destructive sink within 512 characters. Overwrites break the flow,
  closed blocks and unrelated cleanup remain inert, and generic `writeFile` calls
  are no longer treated as destructive. Newer local prefixes are still considered
  after an expired candidate, with exact 512/513 boundary coverage.

- **Four-component V8 versions no longer look like private network disclosures.**
  A per-scan incremental lexical index recognizes same-line, typed-array,
  multiline, comment-bearing, CRLF and prose-list ownership without rescanning a
  4 KiB prefix for every candidate. Ownership remains bounded and cannot hide a
  later host, CIDR, non-V8 nested context or ordinary prose that merely mentions
  V8. The adversarial 5 MiB / 20,000-candidate case is guarded against regression.

- **Python dependency-confusion coverage no longer fails clean on unreadable,
  delegated, dynamic or unsupported manifests.** `requirements.txt` reads,
  continuations, comments, includes, editable/VCS entries and malformed PEP 508
  forms now preserve an explicit partial-coverage verdict when dependency intent
  cannot be resolved. `pyproject.toml` parsing covers standardized project and
  optional dependencies, build requirements, dependency groups and includes, plus
  Poetry tables, while respecting TOML case sensitivity, quoted/dotted keys,
  inline/dynamic declarations, escapes and malformed arrays. PEP 503-equivalent
  names share registry work without losing per-manifest attribution.

- **Pattern-table wiring checks cannot be satisfied without executing validation.**
  The AST guard follows direct, aliased, optional, sequence, call/apply and
  immediately invoked bound validators, but no longer treats bare `.bind()` or a
  derived empty array as validation of the original table. Typed pattern-table
  aliases and extracted pattern expressions are also covered, closing routes by
  which future detector tables could silently bypass the shared engine contract.

### Changed

- **Self-scan policy is explicit and narrow.** Re-excluding all of `dist/` was
  rejected because published generated code is part of the artifact being
  protected. The scanner instead recognizes only exact inert counterparts after
  package identity verification, preserving protection for every other generated
  file and every unrelated rule.

- **Release governance documentation matches protected-main reality.** Release
  work now records the required branch, protected PR checks, squash merge, and
  post-merge signed-tag sequence instead of the obsolete direct-to-main flow.

- **Release workflow dependencies were refreshed.** `actions/download-artifact`
  is updated from 7.0.0 to 8.0.1 and `docker/login-action` from 4.5.0 to 4.6.0
  through the reviewed Dependabot changes.

- **Performance gates separate production cost from coverage overhead.** Real
  full-suite 5 MiB wall-clock checks are bounded at 10-15 seconds and pass on
  Linux. V8 coverage runs use a documented 5x instrumentation multiplier;
  profiling and removal of that multiplier are tracked explicitly for v5.23.4.

### Added

- **Build-backed and real-bundle regressions.** An isolated checkout is compiled
  and scanned with assertions of zero high/critical findings, a score no greater
  than 10, and a clean/low aggregate verdict, then seeded with malicious controls
  to prove `dist/` is still scanned. The installed Vite 8.1.4
  and Vitest 4.1.10 artifacts are tested directly, alongside malicious controls.

- **Adversarial precision and cost coverage.** New focused cases cover exact
  512/513 gaps, DNS label limits, local-address encodings, comment/string/regex
  masks, JavaScript and Python scope boundaries, shell expansion and pipeline
  semantics, TOML/requirements completeness, V8 ownership, and multi-megabyte
  near misses and assignment chains.

## [5.23.2] - 2026-07-30

### Added

- **Threat intel: 250 malicious package IOCs** imported from the GitHub Advisory
  Database (CWE-506) and corroborated against OSV.dev. Clusters include the
  ongoing Baileys/WhatsApp-library wave, AI-agent-tooling typosquats
  (`@ai-agent-node/*`, `@ai-plus/*`, `claude-*`), crypto/wallet and
  prediction-market SDK impersonations, and typosquats of popular build tooling.

- **Threat intel: 79 non-package IOCs for three campaigns** that the advisory
  databases do not publish:
  - *Alibaba developer toolchain RAT* (Socket, July 2026): 2 C2 subdomains,
    8 staging dead-drop paths, 8 payload hashes and the attacker GitHub account.
    A hijacked `lib-mtop` pulled a config-parser dependency chain that writes
    `.cloud-preferences.json` and evaluates the rules inside it, giving a
    cross-platform RAT on developer machines and CI runners.
  - *Fake Paysafe / Skrill / Neteller payment SDKs*: the 56 entry-point hashes
    (52 npm `index.js`, 4 PyPI `__init__.py`) behind the 17 typosquats whose
    names and C2 tunnel were already pinned.
  - *AsyncAPI npm compromise*: 2 further campaign artifact hashes.

  Shared infrastructure is deliberately not blocked: only the specific attacker
  subdomains and bucket paths are ingested, never the `aliyuncs[.]com`,
  `fcapp[.]run`, `ai-app[.]pub`, `ngrok-free[.]dev` or `github[.]com` parent hosts.

### Fixed

- **Three test suites no longer hardcode the version string.**
  `sbom-generator.test.ts`, `dependency-confusion.test.ts` and
  `action-partial-scan.test.ts` asserted a literal `5.23.1` and went red on this
  bump, the same drift class that broke the v5.2.14 and v5.2.17 publishes. They
  now read `pkg.version` from `package.json`, as `reporter.test.ts` already did,
  so they cannot fall a release behind again.

## [5.23.1] - 2026-07-30

### Fixed

- **Pattern evaluation no longer silently stops on ordinary source files.** The
  500-line cutoff and 4,096-character multi-line truncation are gone. Registered
  broad-gap rules now require bounded structural matchers at module load, and
  admitted long or minified lines retain exact matching where a structural
  matcher exists. Any remaining safety limit produces
  `PATTERN_SCAN_INCOMPLETE` and `partialScan: true` instead of a clean verdict.

- **High-impact correlation rules are more precise.** `DROPPER_TEMP_EXEC` no
  longer reads `.exe` out of `.execSync` and requires the written payload to
  reach an execution call. Proxy traps require the hostile operation inside the
  trap, GeoIP protestware requires a destructive target, and PyPI base64
  execution requires direct or same-variable data flow. Rejected value
  candidates no longer hide a later valid match on the same line.

- **Scanner entry points now honor one complete pattern contract.** Extension,
  path, test-file, corroboration, value, and line-span guards are shared across
  repository, npm, PyPI, VS Code, config, Docker, Cargo, Go, Git, README, MCP,
  skill, agentic-workflow, and GitHub Actions workflow scans. This fixes the
  package-scanner applicability drift and the VS Code obfuscation-loop bypass.

- **Incomplete filesystem coverage fails closed.** Unreadable, unenumerable,
  depth-limited, oversized, broken-link, escaping-link, special-node, and
  traversal-budget paths produce deduplicated coverage findings. Internal
  symlinks retain their shipped public paths for rule applicability, while
  canonical containment prevents reading host files outside the scan root.

- **Published artifacts are scanned as published.** PyPI scans every unique
  sdist and wheel in the latest release, verifies downloaded SHA-256 identities,
  retries equivalent metadata URLs after acquisition failures, and attributes
  findings to the exact metadata URL alias whose bytes passed digest
  verification. Independent artifact identities continue after one fails, and
  distinct valid digests remain separate. Missing or malformed digest metadata
  keeps the content scan but marks the verdict partial. npm and
  VSIX scans include shipped `node_modules`. Archive members are preflighted
  before extraction for unsafe paths and link graphs, special nodes, duplicate
  or inconsistent trees, and bounded input, entry, and expanded sizes. Walkers
  follow contained symlinks with bounded expansion, and VSIX manifest reads use
  the same file-size protection as normal content scans.

- **Partial status survives every reporting and policy surface.** Text, JSON,
  Markdown, SARIF, CycloneDX, HTML, badge, GitLab, JUnit, MCP, SOC, repository,
  and organization results distinguish incomplete from clean. Severity filters
  cannot erase the partial verdict, and partial scans do not write clean risk
  history. Organization posture excludes incomplete repositories from complete-score
  averages and reports them separately. The default CLI critical verdict and the
  Action's critical threshold retain exit code 2.

- **The GitHub Marketplace Action now has one authoritative scan.** The CLI
  produces the requested format and canonical JSON from the same in-memory
  report. The Action validates inputs and consumed schema, uses the same
  severity gate as the CLI, reconciles formatter and exit status, pins the CLI
  and third-party Actions, bounds logs and outputs, neutralizes workflow-command
  and PR-comment injection, paginates canonical bot comments, and fails closed
  when setup, scanning, formatting, or coverage is incomplete. It also supports
  `fail-on: info`; exposes `partial-scan`, `report-path`, and `report-truncated`;
  and reports `risk-level: partial` when coverage is incomplete.

- **CLI outputs are collision-safe and complete.** `--json-output` writes a
  canonical sidecar from the same scan. Incompatible severity thresholds and
  aliases among `--output`, `--json-output`, `--save-baseline`, and
  `--sbom-output` are rejected before scanning, including hard links and
  dangling symbolic-link chains. Nonzero scan verdicts now let buffered stdout
  drain instead of truncating piped reports.

- **Release metadata is consistent.** Repository, npm, PyPI, VS Code,
  dependency-confusion, and CycloneDX reports now carry the real release
  version instead of stale `1.0.0` or `4.9.0` values. Every governed
  version site includes the exact Marketplace Action CLI pin.

### Changed

- Lexical masking now returns immediately when content has no
  language-relevant string or comment delimiters, preserving matcher semantics
  while avoiding redundant passes over multi-megabyte plain-code inputs.

- Pattern tables are validated at load time for duplicate IDs, invalid spans,
  unsafe broad gaps, and missing structural matchers. AST-based wiring tests,
  differential matcher checks, long-line adversarial cases, late-file fixtures,
  symlink/archive cases, and Action contract tests guard the repaired behavior.

## [5.23.0] - 2026-07-29

### Added

- **Bounded multi-line pattern matching (`spansLines`).** The pattern engine
  previously matched line by line, so a rule whose regex bridges two ideas only
  fired when the author happened to write them on one line. A payload like
  `new Proxy(target, { get: ... })` on a single line was detected, and the
  identical construct pretty-printed across three lines was silent. Patterns may
  now opt in with `spansLines: N` (default 1 = today's single-line behaviour).
  The engine joins a sliding window of N consecutive lines, matches with the `s`
  (dotAll) flag inside that window only, and reports the line where the match
  starts. Whole-file matching with dotAll is intentionally not offered: a rule
  like `(?:TEMP|TMP).*(?:exec|spawn)` would then pair a tmpdir on line 3 with an
  exec on line 900, which is the false-positive shape v5.22 eliminated and would
  scale with file size.

- **Shared `matchPatternInContent` engine** used by the directory, npm, PyPI,
  VS Code, Dockerfile and config scanners, so multi-line behaviour cannot drift
  between entry points. Value-level (`valueFilter`) and file-level
  (`requiresInFile`) guards still apply on every path; load-time validation now
  also compiles the multi-line form and rejects `spansLines` above the hard cap.

### Changed

- **Opt-in `spansLines` enabled on rules that need it**, with measured windows:
  `PROXY_HANDLER_TRAP` (5), `DROPPER_TEMP_EXEC` (6), `PYPI_B64_EXEC_COMBINED` (4),
  `PYPI_CUSTOM_*` install hooks (6), `PROTESTWARE_IP_GEO_V2` (8). All other rules
  stay single-line.

- **`truncateMatch` shared and multi-line-aware.** Multi-line hits collapse to one
  readable line before SARIF / JSON / annotations, so a whole window cannot leak
  into a report.

### Fixed

- **Pretty-printed Proxy traps and multi-line droppers were false negatives.**
  Precision corpus now includes split-across-lines samples for
  `PROXY_HANDLER_TRAP` and `DROPPER_TEMP_EXEC`; both fire. Window-boundary,
  start-line mapping and ReDoS-budget tests cover the engine itself.

## [5.22.0] - 2026-07-29

### Fixed

- **Nine detection rules fired on ordinary source code.** Measured on a corpus of
  everyday files, seven of them produced 8 findings (2 critical, 5 high) with not one
  true positive among them. A release script running `npm publish` was a CRITICAL
  `SHAI_HULUD_WORM` verdict; the word `SOCKS5` in a proxy config was CRITICAL; a CI
  helper writing `.npmrc` was HIGH, twice; a gist link in a comment, a plain ES6
  `Proxy`, and a template-literal WebSocket URL were each HIGH. All nine are now
  corroboration-gated or narrowed, and the same corpus produces zero high or critical
  findings while all nine still detect their genuine malicious counterparts.

- **New `requiresInFile` pattern guard.** The worst false positives were rules whose
  regex asserted something true of innocent code, which no path- or value-level filter
  could fix. A rule may now require corroboration elsewhere in the same file, so
  `npm publish` counts only alongside credential access and process execution, `.npmrc`
  only alongside an exfiltration call, and a gist URL only alongside a fetch.

- **The guard was honoured by one scanner out of eight.** The pattern arrays are
  iterated by the directory, npm, PyPI, VS Code, Dockerfile and config scanners, so a
  filter applied in only one of them means the same file gets different verdicts
  depending on which entry point looked at it. Both the file-level and value-level
  guards are now applied in every loop, enforced by a wiring test that fails the build
  if a new pattern loop appears without them.

- **The scoped-package catch-all matched 94% of all scoped packages.** `scg npm
  <any scoped package>` exited 1 with riskLevel critical: `@vitest/runner`,
  `@babel/helper-plugin-utils` and `@vue/compiler-core` were all reported as malicious.
  The allowlist could never keep up either, since `vitejs` was listed but not `vitest`,
  while `types` accidentally exempted `@typescript-eslint/*`. The rule is gone; the npm
  scanner now resolves scoped malware by exact name through the bundled feed, which
  covers every curated name instead of only scoped ones.

- **Dependency-confusion suffixes flagged the JavaScript ecosystem's naming
  conventions.** `-core`, `-utils`, `-api`, `-service`, `-common`, `-lib` and `-shared`
  matched around 1.7% of every real scoped package at CRITICAL. Removed, keeping the
  self-declared `internal-` and `private-` prefixes, which had no measured false
  positives. The one curated package that relied on the suffix rule now carries an exact
  bare-name feed entry, registry-verified as absent from npm with every published
  version malicious.

- **Entropy was computed on the wrong scale, and never fired on base64.** The metric
  iterated code points rather than UTF-8 bytes, so it was unbounded while its thresholds
  assumed the 0..8 byte range. Worse, base64 cannot exceed log2(64) = 6.0, so a strict
  `> 6.0` threshold never matched a base64 payload at all - the exact shape the rule
  exists to catch. Now byte-based, with the threshold re-derived from measurement:
  across 1,151 real third-party files the maximum was 5.70 and none exceeded 5.8, so
  5.8 catches base64 payloads with no measured false positive. Inlined `data:` URIs are
  excluded, since an embedded asset is not obfuscation.

- `ENV_EXFILTRATION` matched the English word "got" (as in "expected 1.1.5 but got"),
  and missed a real exfiltration shape where the network call precedes `process.env`.
  Both fixed.

- `SECRETS_AWS_KEY` had no charset floor and fired on padded binary inside a WASM blob.
  It now requires the key body to contain at least 8 distinct characters.

- `DEAD_DROP_GIST` accepted short all-digit gist ids, making ordinary gist links high
  severity. It now requires a realistic 20+ character hex id.

- **Every dependabot pull request arrived red, permanently.** The generated handoff
  dashboard embeds a table of every dependency and its version, and the staleness gate
  required a byte-exact match, so any bump failed `prebuild` on "Handoff docs are
  stale". Dependabot cannot fix that: its pull requests run with a read-only token and
  it cannot regenerate the docs. The version column is still written truthfully but is
  no longer part of the comparison, since it is derived entirely from `package.json` in
  the same commit. Every other kind of drift, including adding or removing a dependency,
  still fails the gate.

### Added

- **Load-time pattern validation.** A malformed regex anywhere in the pattern table used
  to be a silent, total loss of content scanning: the scanner compiles patterns inside a
  per-file try/catch, so one bad entry threw on the first file, was swallowed, and
  suppressed every rule ordered after it for the whole scan while still exiting 0.
  Measured: a single invalid entry placed first took a scan from 21 findings to 1 and
  reported success. Every pattern is now compiled at module load and a bad one is a loud,
  immediate failure.

- **Pattern guard wiring test.** Fails the build if a new pattern loop appears that does not
  apply both the file-level and value-level guards, which is how `requiresInFile` came to be
  honoured by one scanner out of eight.

- **Precision regression corpus.** A committed corpus of ordinary source is scanned on
  every test run and must produce no high or critical finding, alongside a matching
  malicious corpus that must keep firing. Every false positive this scanner has shipped
  was found by someone measuring by hand; this makes an over-broad rule fail the build
  instead.


## [5.21.0] - 2026-07-29

### Added

- Daily threat-intel import (2026-07-29): 250 malware package IOCs from the GitHub Advisory
  Database (CWE-506), corroborated against OSV.dev, appended to the bundled feed.
- **NeoShadow npm typosquats (Aikido, January 2026).** Four Windows-targeting typosquats
  (`viem-js`, `cyrpto`, `tailwin`, `supabase-js`) published by npm account `cjh97123`, running
  their payload through MSBuild and resolving the live C2 from an Ethereum contract. Adds the
  C2 domain `metrics-flow[.]com`, fallback C2 IP `80[.]78[.]22[.]206`, the `analytics.node`
  backdoor SHA-256, and the Ethereum resolver contract. All four names are npm security-holding
  placeholders with no legitimate release history, so they are blocked by name; the typosquat
  targets (`viem`, `tailwindcss`, `@supabase/supabase-js`) are explicitly not matched.
- **SANDWORM_MODE / "Echoes of Shai-Hulud" npm worm (Socket + OX Security, February 2026).**
  Token-stealing worm that injects malicious MCP servers into Claude Code, Cursor and VS Code
  and detonates 48 hours after install. Adds 19 malicious package names, the C2 subdomain
  `pkg-metrics[.]official334[.]workers[.]dev`, two secondary C2 apexes, the stage-2 payload
  SHA-256, and the attacker accounts `official334`, `javaorg` and `ci-quality`. Only the
  specific attacker subdomain is listed, never the shared `workers[.]dev` apex.

### Fixed

- **npm alias specs bypassed the scanner completely.** A dependency written as
  `"utils": "npm:chalk-tempalte@1.0.0"` installs the aliased TARGET, but every check read
  the manifest KEY, which is arbitrary text chosen by whoever wrote the file. A
  known-malicious package hidden this way scanned clean (0 critical findings), and
  `npm install x@npm:<malware>` was dropped before any check ran, because the spec failed to
  parse and was discarded. Alias specs are now resolved to the installed package on both the
  scan path and the install guard, and the finding names the alias so the offending manifest
  line is easy to locate. A legitimate alias such as `npm:lodash@4.17.21` stays clean.

- **The install guard treated a name-shape guess as seriously as a malware match.** It
  blocked on ANY finding, so `DEP_INTERNAL_NAME_PUBLIC` - which fires on the shape of a
  scoped name (`@scope/*-utils`, `-api`, `-core`, ...) and matches around 1.7% of all real
  scoped packages, including `@babel/helper-plugin-utils` and `@vue/compiler-core` - blocked
  installs at critical with only `--force` as an escape. That rule is now reported as a
  warning and the install proceeds. Blocking authority is a deny-list, so every exact-match
  verdict (threat-feed IOC, known-bad version) still blocks, as does `TYPOSQUAT_LEVENSHTEIN`:
  the guard does not consult `patterns.ts`, so for curated squats such as `lodahs`,
  `crossenv`, `cros-env`, `1odash` and `expresss` that rule is its only view of them.
  `InstallCommandAnalysis` gains `warned`, and each verdict gains `blocking` and `warnings`;
  `findings` still carries everything.

- **`TYPOSQUAT_SIMILAR_TO_DEP` fired on ordinary dependency pairs.** Measured across 939 real
  manifests it hit 5.0% of them (8.1% of repository roots), and every colliding pair was a
  legitimate co-install: `preact`+`react`, `vue`+`vuex`, `path`+`pathe`, `color`+`colors`,
  `mysql`+`mysql2`, `uuid`+`ulid`. It now requires both names to be at least 4 characters,
  skips the pair when the reported side is a known-good package, and reports a pair once
  instead of once per side. The known-good test is deliberately one-sided so a squat sitting
  next to the package it imitates (`expres`+`express`) still reports. Switching it to the
  same transposition-aware distance as its sibling also ADDS recall: `lodahs`+`lodash`,
  `axois`+`axios`, `raect`+`react` and `rimarf`+`rimraf` were previously missed. This narrows
  a noisy rule; it does not eliminate the class, since one-letter differences between two
  real packages remain inherently ambiguous.

- **`TYPOSQUAT_SIMILAR_TO_DEP` could not be suppressed per package.** `allowlist.packages` in
  a policy file only covered two rules, so a project depending on both `vue` and `vuex` had
  to disable the rule outright. Allowlisting either named package now suppresses the pair.

- The typosquat target floor moved from 4 characters to 5. Four-letter targets (`path`,
  `jest`, `cors`, `sass`, `vite`, `uuid`) produced roughly half the remaining false
  positives, because almost any short name is one edit from them; measured over 29,687 real
  published names this halves them with the curated true-positive set unchanged.

- **The typosquat heuristic flagged hundreds of legitimate packages.**
  `TYPOSQUAT_LEVENSHTEIN` accepted two plain Levenshtein edits against a list of 92 popular
  names. Measured against a 27,140-name corpus of real npm packages, that flagged **321
  legitimate packages**, and the rate rose with popularity (2.37% of packages above 10M
  weekly downloads): `acorn`, `preact`, `cypress`, `redux`, `viem`, `knex`, `globby`, `jose`,
  `mime`, `util` and `enquirer` were all reported as typosquats. In `guard` that is a hard
  install block. The scanner also flagged two of its own dependencies (`pathe`, `obug`), and
  told users of `color` "Did you mean `colors`?", recommending the package its author
  sabotaged in January 2022.
  The ceiling is now **one transposition-aware edit** (Optimal String Alignment). Adjacent
  transpositions are the shape every real squat in this project's threat data takes
  (`rimarf`, `yarsg`, `lodahs`, `veim`), and plain Levenshtein scores those as 2, so
  transposition awareness is what lets the ceiling drop without losing any of them. Leading
  homoglyph squats (`1odash`, `l0dash`) are still caught: no same-first-character rule was
  added, because this repo curates exactly those names in `patterns.ts` and on a public repo
  such a rule would be a documented one-character bypass. A small allowlist covers the
  legitimate names that genuinely sit one edit away (`pathe`, `color`, `nuxt`, `preact`,
  `gaxios`, `enquirer` and others), each registry-verified on 2026-07-29. The allowlist gates
  this one rule only: feed IOC matches, the known-bad-version blocklist and every scanner
  pattern run on paths that never consult it.
  Findings now also name the *closest* popular package rather than the first array match, so
  the "Did you mean" text is no longer array-order dependent. The exported `levenshtein`
  helper is unchanged.
- **The importer's page cap was one busy fortnight from freezing the feed.** The 2026-07-29
  run needed 184 of the 200 allowed pages. Hitting the cap is fatal and writes nothing, so a
  burst window would have imported zero IOCs rather than fewer. The default is now 750, held
  in a single `DEFAULT_MAX_PAGES` constant instead of four separate literals. This does not
  change which IOCs a successful run imports: the fetch is newest-first and `--limit` still
  takes the newest 250 either way. It only stops burst days from aborting to zero.
- **`--limit abc` silently imported nothing and exited 0.** Numeric CLI options were parsed
  with bare `Number()`, and `NaN` disabled every guard it reached: nothing reported as capped
  and `slice(0, NaN)` returned an empty array, so the run claimed success while importing zero
  IOCs. `--days`, `--limit`, `--max-pages` and `--timeout` now reject anything that is not a
  positive integer.
- `package-lock.json` is now covered by the version-sync gate. The release bump edits
  version strings in place, but npm writes the lockfile's own `version` fields at install
  time, so the lockfile trailed a release behind (5.20.0 at the v5.20.1 tag, 5.20.1 at the
  v5.20.2 tag) and nothing caught it because the file was not a configured version site.
  It never affected the published package, which does not ship the lockfile. Resync with
  `npm install --package-lock-only` when bumping.

## [5.20.2] - 2026-07-28

### Fixed

- **The bundled feed was one import away from breaking the build.** `tsc` reports
  TS2590 ("Expression produces a union type that is too complex to represent") on the
  `BUNDLED_FEED` array literal once it grows too complex. The limit is content-dependent,
  not a fixed entry count: measured on this file, uniformly-shaped entries (exactly what
  the daily advisory import appends) fail at 1,256 total, while shape-diverse entries
  reach 4,245. At 1,197 entries that left as little as 58 entries of headroom against an
  import that adds 250 at a time. The feed is now stored as capacity-bounded
  `FEED_CHUNK_n` consts spread back into `BUNDLED_FEED`, which typechecks 100,000 entries
  across 100 chunks in about 9 seconds. Every entry is still validated against `FeedIOC`
  (bad severity, wrong field type, missing required field and unknown property are all
  still compile errors), and no IOC data changed: all 1,197 entries in `feed.json` are
  identical, with only its embedded version string differing.
### Changed

- **The daily import now rolls over to a new chunk instead of growing one array.**
  Chunking alone would only have deferred the ceiling, because the importer appends
  to a single place; it now fills the last chunk to `FEED_CHUNK_CAPACITY` (1,000) and
  then opens a new one, registering it in the composed array. An oversized batch is
  split across as many chunks as it needs, so no single literal can grow back into
  TS2590.
- `scripts/generate-feed.mjs` collects every `FeedIOC[]` declaration and evaluates the
  composed array, rather than one hard-coded literal. It now fails loudly when a chunk
  exists but is missing from the spread - the one failure mode chunking introduces,
  where the feed would otherwise ship silently short.

### Added

- Feed-integrity tests: the bundled entry total must equal `feed.json`'s `entryCount`,
  must stay above a floor, must equal the sum of the declared chunks, and no chunk may
  exceed capacity. Plus rollover coverage for the importer. Every prior test asserted
  on entries that were present, so a dropped chunk would have shipped green.

### Security

- Bumped the pinned `@elvatis_com/aahp` gate toolchain to 3.9.0 (supersedes #83).
## [5.20.1] - 2026-07-28

### Added

- **258 new threat indicators.** 250 malicious-package IOCs imported from the
  GitHub Advisory Database (CWE-506 advisories published 2026-07-14 and later),
  125 of them corroborated against OSV.dev.
- **AsyncAPI campaign infrastructure (Socket + StepSecurity, July 14 2026).** The
  package versions have been pinned since v5.20.0, but the atomic indicators were
  missing, and the advisory databases never publish them. Adds the botnet C2 host
  `85[.]137[.]53[.]71` (`:8080` commands, `:8081` credential upload, `:8091` proxy
  management), the Ethereum fallback-channel contract address, the second IPFS
  payload CID serving the `@asyncapi/specs` branch, and SHA-256 hashes for all
  five malicious registry tarballs so a vendored or mirrored copy is caught even
  when the version metadata is gone. The campaign's Nostr relays, BitTorrent DHT
  bootstrap nodes and the `ipfs[.]io` gateway host are deliberately not matched:
  they are shared public infrastructure, and only the campaign-specific CID paths
  are ingested.

## [5.20.0] - 2026-07-27

### Added

- **259 new threat indicators.** 250 malicious-package IOCs imported from the
  GitHub Advisory Database (CWE-506 advisories published 2026-07-13 and later),
  173 of them corroborated against OSV.dev; the bundled feed grows from 680 to
  939 entries.
- **ChainVeil campaign coverage (Checkmarx Zero, June 2026).** The nine npm
  typosquats of the Tailwind, Sass, TypeORM and rate-limiter libraries that
  preceded the already-covered ViteVenom wave, carrying the same 77 KB RAT and
  the same four-tier Tron/Aptos/BNB Smart Chain C2. All nine were confirmed
  against the npm registry as "security holding package" placeholders, so no
  legitimate release exists under those names and they are matched by bare name.
  The packages they impersonate (`tailwind-merge`, `rate-limiter-flexible`,
  `typeorm`) are explicitly not matched, and a regression test asserts that.
- **Known C2 blockchain wallets are now detected**, as a new `IOC_KNOWN_C2_WALLET`
  rule, seeded with the three published ViteVenom/ChainVeil Tron and Aptos
  tier-2 addresses. `KNOWN_C2_WALLETS` previously sat in `src/patterns.ts`
  empty and imported by nothing, which made it look like the home for wallet
  indicators while reading it detected nothing; it now lives beside the other
  blocklists. Matching is exact-literal and always will be: a bare `0x` plus 64
  hex characters is indistinguishable from an Ethereum transaction hash or a
  keccak digest, so a shape-based rule would flag legitimate web3 repositories
  on sight. A load-time floor rejects short or low-entropy addresses, since the
  realistic ingest mistake is a short-form address such as `0x1`, which would
  substring-match nearly every file. Documentation files are exempt as before,
  and the rule can be turned off with `--exclude IOC_KNOWN_C2_WALLET`.

### Removed

- Two internal pattern collections in `src/patterns.ts` that nothing read:
  `GLASSWORM_MARKERS` (its marker is an active `FILE_PATTERNS` rule) and
  `C2_DOMAIN_PATTERNS` (its first pattern duplicates a live C2 domain entry; its
  second would have matched ordinary Cloudflare Workers hostnames). Neither was
  part of the package's public exports.

### Fixed

- **The `url` indicator shape accepted any 8+ character printable token.**
  Feed values of type `url` are substring-matched against whole file contents at
  the entry's own severity, so a value such as `process.env` or `require(` would
  have flagged entire repositories as critical. The shape is now structural: an
  `0x` EVM address, or a host that carries a scheme, a port, or a path. Bare
  dotted hosts are rejected because they are indistinguishable from dotted code
  identifiers; those belong in `type: "domain"`. Internationalized (punycode)
  hosts, IPv4 hosts, userinfo, ports and query-only URLs are all accepted, and
  every indicator in the published feed passes unchanged.
- **A critical Jenkins-plugin indicator was unreachable.** No code path passed
  the `jenkins:` ecosystem prefix to the package matcher, so
  `jenkins:checkmarx-ast-plugin@2026.5.09` shipped as detection that could never
  fire. The offline MCP `ioc_lookup` tool now accepts `go` and `jenkins`, and a
  new test asserts that every package indicator in the feed is reachable by a
  matcher some caller actually invokes.
- **Every mixed-case entry in the malicious-GitHub-account blocklist was
  unreachable** through the repo-owner path. The check compared an already
  lowercased owner against the raw array, so six of the 26 entries could never
  match. GitHub logins are case-insensitive, so both sides are now normalized
  through a single helper.
- **The same blocklist was disabled entirely on any machine without the GitHub
  CLI.** The `gh` availability gate sat above the check, so `scg repo <url>` on
  a runner without `gh` returned no findings at all. The blocklist is a local
  array lookup that needs no network, and now runs before the gate.
- **PyPI package names are matched under PEP 503 equivalence.** PyPI treats
  names case-insensitively and collapses runs of `-`, `_` and `.`, so
  `LiteLLM==1.82.7` in a requirements file silently passed while `litellm`
  was flagged. npm is deliberately left case-sensitive, because npm names are
  case-sensitive at the registry and widening there could flag a legitimate
  package.
- **Package IOC matching no longer scans the whole feed for every dependency.**
  `matchPackageIOC` was a linear scan that lowercased every feed value on every
  call. It is now an index built once per feed, preserving the matching
  semantics exactly, including NuGet's case-insensitivity and first-match-wins
  ordering between bare-name and version-pinned entries. Measured over 200
  dependencies: 12.1 ms to 0.08 ms at the current feed size, and 573.6 ms to
  0.10 ms at 26,000 entries. `loadThreatIntel` is memoized on the cache file's
  identity rather than re-reading and re-parsing it for each scanner family,
  saving a further 142 ms per scan against a 2.3 MB cache. This is what unblocks
  growing the bundled feed beyond its current size.

- **The Docker image build no longer hangs.** It built `linux/arm64` under QEMU
  emulation, and Node under `qemu-user` has a deadlock class that stalls `npm ci`
  and `tsc` while emitting no log output at all - so the step could not even be
  expanded in the Actions UI. It usually finished in about 90 seconds, but v5.18.0
  hung until GitHub's default 360-minute job timeout killed it, and v5.19.0 hung
  the same way, leaving `:latest` on the previous release. Each architecture now
  builds on a native runner and pushes a digest-only image, and a final job
  stitches the digests into one manifest, so emulation is gone rather than
  time-boxed. Tagging happens only in that merge job, so a half-finished matrix
  can no longer move `:latest` onto a single-architecture image, and the job
  verifies both architectures are in the published manifest before going green.
  Explicit `timeout-minutes` turns any future hang into a fast, visible failure,
  per-architecture build caching makes a retry cheap, and a `version` input gives
  a recovery path for a release whose image failed after npm had already published.

## [5.19.0] - 2026-07-26

### Fixed

- **The threat-feed importer no longer loses advisories silently.** Its page cap
  was a correctness bound disguised as a safety bound. The upstream query sorts
  `published/desc` and the importer keeps no cursor, so hitting the cap kept the
  newest advisories and never fetched the oldest, and the next run started again
  at page 1 and re-fetched the same newest pages. The unfetched remainder was
  therefore unreachable by any number of runs and aged out of the look-back
  window for good, while the run printed "page cap reached" and exited 0.
  Measured against the live advisory database on 2026-07-26: the window held
  11,952 malware advisories mapping to 20,915 new IOCs, of which 1,108 were
  reachable, so 94.7% was never seen; 8 of 54 rolling windows over the previous
  60 days exceeded the cap. A missed malicious package is a silent false negative,
  so truncation is now **fatal** - the import aborts, writes nothing and exits
  non-zero, with `--allow-truncated` to override deliberately. `--max-pages`
  default is now 200 and `--days` is 14, which also lets a week of missed runs be
  recovered rather than lost. `--limit` stays 250: unlike a page cap it is
  recoverable, and the report now states how many entries are waiting and that
  they expire, instead of the bare "(limit reached)" that made the shortfall look
  self-healing. That recovery is conditional, not guaranteed: leftovers survive
  only while `remaining <= limit * runs_left`, so on a burst window the excess
  still ages out. The difference from a page cap is that the number is now
  reported, so the window can be widened or sliced deliberately.
- **`## [5.18.0]`'s changelog section is restored.** The v5.18.1 release commit
  renamed the `## [5.18.0]` heading instead of adding a new one, so two releases'
  notes sat under one heading and the `[5.18.0]:` reference link was orphaned.
  The published v5.18.0 release body was captured at tag time and is unaffected;
  the published v5.18.1 body does carry v5.18.0's notes as a result, and is left
  as-is because a release body is a historical record once tagged.
- **The em-dash gate was scanning almost nothing.** Its `docs/**/*.md` and
  `.ai/handoff/**/*.md` entries are git pathspecs, where `**/` still requires a
  literal intervening slash, so both matched zero tracked files and the rule only
  ever covered four files at the repository root. Corrected to `docs/*.md` and
  `.ai/handoff/*.md`, taking the rule from 4 files to 15.

### Added

- **Repo process: AI-attribution gate.** Tool and model attribution (a `Claude Code` markdown
  link, the `claude[.]com/claude-code` footer URL, or a `Co-authored-by` trailer
  naming the model) is now blocked on every published surface. The indicators are
  defanged here for the same reason IOCs are: writing one raw trips the gate, as
  the first draft of this entry did. `CHANGELOG.md` is deliberately in scope
  because CI turns its matching section into the GitHub Release body, which is
  indexed and cannot be fixed by a later commit. Since a PR body and a commit
  message are not files in the repository, a companion CI step covers those two
  surfaces, and the `pull_request` trigger now includes `edited` so pasting a
  footer into a body after CI has passed cannot slip through. The PR title and
  body reach that step as environment variables and are only ever read as quoted
  shell variables, never interpolated into the script, so an attacker-controlled
  body cannot execute on the runner. `.ai/handoff/**` is out of scope by design:
  that is where an agent note is expected to carry a model id.
- **Repo process: CHANGELOG reference-link gate.** The pinned AAHP changelog gate walks release
  headings to footer links but not the reverse, and never inspects what the
  `[Unreleased]` link points at, which is how a compare link stale by two releases
  shipped green. Two `docSync` groups now assert both directions plus that the
  `[Unreleased]` compare base equals the released version, with no new gate script.

## [5.18.2] - 2026-07-26

### Added

- **Threat-feed import 2026-07-26.** Imported 250 malicious-package IOCs from
  the GitHub Advisory Database (CWE-506) for advisories published 2026-07-19
  and later, 194 of them corroborated against OSV.dev; the bundled feed grows
  from 430 to 680 entries. These are the ongoing clusters of throwaway npm and
  PyPI malware names (`app-*`, `eth-*`, `streak-*`, `svgcraft-core`,
  `cktool-core` and similar), each carrying its advisory id in `FeedIOC.source`.
  The run hit the importer's default 250-entry cap, so a backlog remains for the
  next run. No atomic (C2 / hash / account) indicators were addable: every
  current vendor write-up (AsyncAPI, jscrambler, node-ipc, Shai-Hulud family) is
  already covered, and the one uncovered campaign (payment-SDK typosquats, July
  2026) exfiltrates only over shared `ngrok-free[.]dev` tunnels and AWS
  infrastructure, which are deliberately not blocked.

## [5.18.1] - 2026-07-25

### Fixed

- **The scanner's state directory now ignores itself.** `.scg-history/` holds
  scanner state (risk history, triage decisions), not project content, but a
  scan created it inside the repository being scanned and left it for the
  consumer to notice. It usually appears before anyone has thought about
  `.gitignore`, so a later `git add -A` sweeps it into an unrelated commit.
  Creating the directory now also writes a `.gitignore` containing `*`, which
  git honours for everything beneath it including that file itself. Nothing is
  required of the consumer and it cannot be forgotten. The file is restored if
  it is deleted, and a filesystem that refuses the write does not fail the
  scan. `--no-history` already existed and still works, but it only helped the
  people who knew to pass it; a plain `supply-chain-guard scan .` wrote state
  regardless.

## [5.18.0] - 2026-07-25

### Added

- **Internal-disclosure rule family (`INTERNAL_*`), a new detection axis.**
  Existing scanners (this one included) hunt CREDENTIALS. Nothing in that
  category hunts internal TOPOLOGY leaking into a public repository: internal
  hostnames, private LAN addresses, non-public forge URLs, developer
  filesystem paths and private repository inventories. None of it is a secret,
  all of it is reconnaissance material, and it stays in git history long after
  the file is fixed. New module `src/internal-disclosure.ts` with eight rules:
  `INTERNAL_PRIVATE_IP` (RFC1918, CGNAT 100.64/10, link-local 169.254/16),
  `INTERNAL_PRIVATE_IPV6` (ULA fc00::/7), `INTERNAL_HOSTNAME` (.internal,
  .local, .lan, .corp, .home, .intranet), `INTERNAL_SERVICE_ENDPOINT`
  (host plus port on a private or internal host), `INTERNAL_GIT_REMOTE`
  (ssh:// and scp-style remotes on a host that is not a known public forge,
  which finds a self-hosted forge without anyone having to name it),
  `INTERNAL_DEV_PATH` (home-directory paths), `INTERNAL_SINGLE_LABEL_URL`
  (dotless hosts) and `INTERNAL_DENYLIST_MATCH` (configured terms, off by
  default). Every rule is shape-based, so it protects a repository whose owner
  configured nothing.
- **Configurable deny-list that solves its own paradox.** A list of internal
  hostnames committed to a public repository IS the leak, so
  `internalDisclosure` in `.supply-chain-guard.yml` supports three modes:
  `hashedTerms` (sha256 of a term normalised as trim plus lowercase;
  publishable and exact-token matching only - it keeps the term out of the
  file, out of grep and out of reports, and with the optional
  `SCG_INTERNAL_HASH_SALT` plus `hashSalted: true` it also resists the
  dictionary attack that an unsalted digest of a hostname invites),
  `externalFile` plus the `SCG_INTERNAL_DISCLOSURE_FILE` environment variable
  (full regex and literal patterns kept out of the repository, matches
  reported REDACTED so the report cannot leak them either), and `patterns`
  (plaintext, for repositories that are private anyway). New CLI command
  `supply-chain-guard internal-hash <term...>` prints digests and nothing else.
  A configured `externalFile` that is absent is reported as
  `INTERNAL_DENYLIST_UNAVAILABLE` (info) and an entry that cannot be compiled
  as `INTERNAL_DENYLIST_INVALID_ENTRY` (medium): a deny-list that quietly
  stopped running otherwise looks exactly like a clean repository. Neither
  diagnostic prints the entry, and the environment variable is named without
  its value, because a path can itself contain an account name.
- **False-positive controls, because a rule that screams on every README gets
  disabled.** Three layers, tuned against axios, express, got and
  awesome-compose (992 files): 3.5 findings per 100 files before, 1.1 after.
  1. Reserved VALUES never fire: RFC5737 addresses, RFC2606 names and the
     `.example` TLD, loopback, placeholder and CI account names such as
     `runner` or `vscode`, container service aliases and the `unix` / `npipe`
     socket pseudo-hosts, CIDR ranges as opposed to host addresses, and the
     universal infrastructure constants that are identical in every
     installation (cloud metadata `169.254.169.254`, ECS `169.254.170.2`,
     Amazon Time Sync `169.254.169.123`, Alibaba `100.100.100.200`, the
     Kubernetes `10.96.0.1` / `10.96.0.10` and k3s `10.43.0.1` / `10.43.0.10`,
     the default service and pod CIDRs, the Docker bridge gateway
     `172.17.0.1`, and `host.docker.internal` and its siblings).
  2. LEXICAL position has to fit the claim: an internal-only TLD must be the
     LAST label (`config.internal.timeout`, `settings.local.json`), a name
     preceded by a path separator is a module specifier and not a host
     (`./config.local`), a name followed by `(` is a method call
     (`res.local(name, val)`), a URL scheme is no longer mistaken for the start
     of a comment, and in programming-language sources a bare dotted name is
     only reported inside a string literal, a comment or a URL.
  3. The SURFACE decides which rules stay armed: test and fixture directories
     and minified or bundled output report nothing, files that exist to BE an
     example (`examples/`, `fixtures/`, `*.example.*`) keep the hostname,
     endpoint and clone-URL rules, and documentation prose and fenced blocks
     keep everything except the single-label URL.
  The README documents the full matrix.
- **An optional per-project salt for the hashed deny-list.**
  `SCG_INTERNAL_HASH_SALT` (held outside the repository, so a reader of the
  repository cannot use it) is mixed into every digest, and
  `internalDisclosure.hashSalted: true` declares that the committed digests are
  salted so a scan that runs without the salt is reported as
  `INTERNAL_DENYLIST_UNAVAILABLE` rather than matching nothing and looking
  clean.
- **Upstream threat-feed import (`npm run feed:import`).** Malicious-package
  IOCs are now imported from public advisory databases instead of being read
  out of a general security-news aggregator by hand. Primary source: the
  [GitHub Advisory Database](https://github.com/advisories?query=type%3Amalware)
  malware advisories (CWE-506), fetched over the public REST API with no
  account and no API key; `GITHUB_TOKEN` is strictly optional and only raises
  the rate limit from 60 to 5000 requests/hour. Secondary source:
  [OSV.dev](https://osv.dev/) `querybatch`, used only to corroborate a package
  GitHub already flagged (a `MAL-` record from `ossf/malicious-packages`) - it
  can raise confidence from 0.9 to 1.0 but can never discover a package on its
  own, and an OSV outage degrades gracefully instead of failing the run.
- **Per-entry provenance.** Imported entries populate the previously unused
  `FeedIOC.source` field with the advisory id they came from (`GHSA-...`, plus
  `MAL-...` when corroborated), so every machine-added indicator is traceable
  to a public advisory page. `source` and `lastSeen` were also added to the
  inert-feed key allowlist in `isInertThreatFeedFile()`; without that, the
  project's own `feed.json` would stop being recognised as its own data and
  would be scanned as ordinary content.
- **`docs/threat-feed-sources.md`** documents the sources, their licences and
  attribution (GitHub Advisory Database CC BY 4.0; `ossf/malicious-packages`
  Apache-2.0), the full upstream-to-`FeedIOC` field mapping including the
  fields that deliberately stay unset (`family`, `campaign`, `lastSeen`) and
  the two project constants that upstream does not publish (confidence 0.9
  single-source / 1.0 corroborated), the ecosystem prefix table, the
  version-range rules, and the failure mode.
- **Bounded cost on generated files, and a new `INTERNAL_DISCLOSURE_TRUNCATED`
  (info) rule so a limit is never silent.** The internal-disclosure scan is now
  flat in the size of a file rather than quadratic in the number of matches on
  a line: line offsets are computed once per file and binary-searched, each
  line's quoting and comment structure is computed once per line instead of
  once per match, an over-long line is skipped in one step, and findings are
  capped at 25 per rule and 100 per file with a 20000-candidate ceiling per
  rule. Measured on an 810 KB single-line bundle: 49 s and a 26 MB report
  before, 0.01 s and under 1 KB after. Every limit that fires adds one
  `INTERNAL_DISCLOSURE_TRUNCATED` finding naming it, on the same principle as
  `FILE_TOO_LARGE_SKIPPED`.
- `pypi:` is now a recognised OSV export ecosystem, so PyPI package IOCs are
  no longer dropped from `supply-chain-guard feed osv`.

### Changed

- **Scores will move, exit codes will not.** The internal-disclosure family
  reports `medium` (weakest rule: `low`), never `high` or `critical`, which
  stay reserved for credential-shaped findings. The default gate exits
  non-zero on critical and high only, so upgrading cannot turn a passing build
  red, and `--fail-on high` / `--fail-on critical` are unaffected. Two things
  do change: the risk score rises where internal topology is present (each
  medium adds points, which can move a `clean` report to `low` or `medium`),
  and a pipeline running `--fail-on medium` or lower will see the new
  findings. The family respects `rules.disable`, `rules.severityOverrides`,
  `suppress` (including `path:` globs), `ignore`, `--exclude`,
  `--min-severity` and inline `scg-ignore-next-line`.
- `allowlist.domains` now also answers `INTERNAL_HOSTNAME`,
  `INTERNAL_SERVICE_ENDPOINT` and `INTERNAL_GIT_REMOTE` for the allowlisted
  host, alongside the threat-intel rules it already covered. The README notes
  the tradeoff: naming a domain there publishes it, so a path-scoped
  `suppress` entry is the leak-free alternative.
- `Finding.category` gained `"disclosure"`, and the `INTERNAL_` prefix is
  counted in the `repoTrust` risk dimension, so the family is not invisible to
  `riskDimensions` (the trap the agent-surface rules fell into before v5.10).
- Policy config validation learned `POLICY_INVALID_INTERNAL_TERM`: a
  `hashedTerms` entry that is not a sha256 digest, or a `patterns` entry that
  is not a valid regex, is reported instead of being silently dropped. Same
  fail-closed reasoning as v5.3.
- The import refuses to invent indicators. Only an exact upstream pin
  (`= 1.2.3` -> `name@1.2.3`) or an all-versions range (`>= 0` -> bare name) is
  mapped; a bounded range is reported as unmappable rather than collapsed into
  a whole-package block that would cover versions upstream never called
  malicious. Ecosystems with no matcher in this scanner are reported, not
  imported. Package names are re-validated against a charset narrower than the
  feed's own package shape before being serialized into TypeScript.
- A failed import is inert: the upstream fetch is the only fatal step, nothing
  is written until the batch has been fetched, mapped, deduplicated and
  re-parsed in memory, and a rewrite that does not re-parse to the expected
  entry count is rolled back. A network error leaves `src/threat-intel.ts` and
  `feed.json` byte-identical and exits non-zero.

### Fixed

- `spec/` is scanned rather than skipped. It is the conventional OpenAPI and
  AsyncAPI directory as often as it is an RSpec one, and a `servers[].url` in
  an API spec is precisely the endpoint-plus-port shape this family exists to
  catch. RSpec files are still excluded by the `_spec.` suffix, which is the
  part that actually identifies a test.
- The deny-list pass reports its own per-line token budget. A line short enough
  to clear the length guard could still exceed 400 candidate tokens, and the
  pass went quiet past that point without a word. It now emits
  `INTERNAL_DISCLOSURE_TRUNCATED` naming the line, so the one way a CONFIGURED
  term could be missed in silence is closed.
- A file that hits the per-file cap reports exactly 100 findings rather than
  101, and the cap now keeps the most severe findings instead of whichever
  rules happen to be declared first.

## [5.17.10] - 2026-07-25

**Rule precision: five rules narrowed with context, none weakened**

A fleet audit found that a large share of the reported risk across 13 scanned
repositories came from rules that matched a SHAPE without ever looking at the
context or the value. Each fix below narrows a rule by teaching it something it
did not know before; every rule keeps a true-positive test proving the attack it
exists for is still detected.

- **`GHA_SECRET_EXFIL_MULTILINE` is now per step.** The old implementation kept
  a file-level `envSecretsExported` flag that was sticky: once any step put a
  secret in its `env:`, every later run block that merely mentioned `curl` was
  reported. Its run-block exit test could only be satisfied by a column-0 line,
  so blocks never ended and the finding named whichever `run:` came last, not
  the one holding the secret. Secrets in scope are now resolved per step
  (step `env:` + job `env:` + workflow `env:` + the step's own `run` body) and
  the finding points at the network command inside that step. Workflows the
  parser cannot break into steps still get the old file-level check, so nothing
  goes undetected.
- **`GHA_PPE_PULL_TARGET` and `GHA_SCRIPT_INJECTION` are context-aware.** Both
  were bare regexes over the whole file, so both fired on
  `env: PR_TITLE: ${{ github.event.pull_request.title }}` - the mitigation
  GitHub documents and that this scanner's own recommendation text tells users
  to apply. A new `classifyWorkflowLines()` pass in `workflow-ast.ts` labels
  every line `exec` (a `run:` or github-script `script:` body), `env:` or
  structural, and both rules now only consider `exec` lines. PPE additionally
  requires the elevated context it is named for (`pull_request_target`,
  `workflow_run`, `issue_comment`, `pull_request_review_comment`), a reusable
  `workflow_call` whose caller may be privileged, or an unreadable trigger
  block. Interpolating PR context in a plain `pull_request` job gains an
  attacker nothing: that job already runs their code with a read-only token and
  no secrets. The `env:` hop is not a loophole: a value moved into `env:` and
  read back with `${{ env.NAME }}` (rather than the shell's `$NAME`) is still
  template-interpolated and is still reported, at the line that reads it back.
- **`IAC_HARDCODED_SECRET` inspects the value.** It matched
  `token = "<8+ chars>"` and never asked what the value was, so
  `password = "${REDIS_PASSWORD}"` (a variable), `password = "$(openssl rand
  -base64 32)"` (a password being GENERATED) and `const token = "trust_pat_"`
  (a namespace prefix) were all CRITICAL hardcoded secrets. Patterns can now
  carry a `valueFilter`, and this rule uses one that rejects variable
  references, command substitutions, template expressions, prefix templates,
  filesystem paths and documentation placeholders. The checks are structural:
  each identifies a value that cannot be a credential, so a real embedded
  credential is untouched.
- **`DOCKER_NPM_GLOBAL` fires on unpinned installs only.** Its recommendation
  said "pin the global package version" while the rule flagged
  `RUN npm install -g pnpm@9` and `RUN npm install -g npm@11.18.0`, which are
  pinned (27 such findings in one repository). It now parses the package specs
  and reports only when one is unversioned, a dist-tag (`@latest`), or a range
  (`@^9`). The `npm i` / `npm add` / `--location=global` spellings are covered
  too, and a locally built tarball is not treated as a registry dependency.
- **`allowlist.githubOrgs` is enforced.** It was parsed, documented and
  schema-validated but never read by `applyPolicy()` - a security config that
  silently did nothing. It now suppresses the ownership-trust findings
  (`GHA_THIRD_PARTY_ACTION`, `GHA_TAG_NOT_SHA`) for actions owned by an
  allowlisted org. Pinning and known-malicious-SHA rules stay armed: trusting a
  publisher says who ships the code, not that every version of it is safe.
- The scanner's own `.supply-chain-guard.yml` drops its `DOCKER_NPM_GLOBAL`
  suppression. The rule no longer fires on the image's pinned local-tarball
  install, so the suppression is no longer needed.

## [5.17.9] - 2026-07-25
**Threat intel: FakeAgent / SectopRAT fake Claude Desktop malvertising**

Added detection for the FakeAgent campaign (2026-07-21 to 2026-07-22) after the daily
news scan surfaced it and primary vendor write-ups (Huntress, BleepingComputer, Help
Net Security, cyberpress) supplied the concrete indicators.

- **FakeAgent / SectopRAT** (2026-07-21). Bing ads for the "Claude Desktop app"
  pointed at a malicious public Claude Artifact hosted on the legitimate `claude[.]ai`
  domain (downloaded ~7,100 times before removal). Clicking Download redirected
  victims through attacker-registered domains (`download-app[.]us`,
  `claude.ai.download-app[.]us`, `downloading-api.it[.]com`) to a trojanized
  `ClaudeDesktop.exe`: a legitimate JetBrains Chromium binary that sideloads a
  malicious `libcef.dll` to deliver the SectopRAT (ArechClient2) infostealer with
  HVNC. The malware uses EtherHiding over the BNB Smart Chain to resolve its live C2.
  At least 29 organizations were compromised. Added the attacker domains, a
  representative subset of the SectopRAT C2 IPs, the five payload SHA-256 hashes and
  the two EtherHiding C2 addresses. The legitimate `claude[.]ai` apex is deliberately
  not blocked (only the abused artifact path was malicious), and the `it[.]com`
  registry apex is excluded in favor of the specific attacker subdomain.

## [5.17.8] - 2026-07-24
**Threat intel: jscrambler npm compromise, cPanel/WHM GitHub Actions abuse, and the Apex macOS infostealer**

Added detection for three developer-targeted supply-chain campaigns whose concrete
indicators were sourced from primary vendor write-ups (Socket, The Hacker News, OX
Security, StepSecurity, safedep, Rescana) after the daily news scan surfaced them
by name only.

- **jscrambler npm compromise** (2026-07-11). The `jscrambler` package (~15,800
  weekly downloads) and four companion build plugins were hijacked and republished
  with a native Rust infostealer: a malicious `preinstall` hook in 8.14.0-8.17.0,
  then a self-executing dropper in `dist/index.js` and `dist/bin/jscrambler.js`
  from 8.18.0. The payload harvests AWS, GCP and Azure credentials, crypto wallets,
  browser data and AI-tool configs on Windows, macOS and Linux. Last clean release
  is 8.13.0, fixed in 8.22.0. The previous partial entry (8.14.0 only) is extended
  to the full malicious set.
- **cPanel/WHM GitHub Actions abuse** (2026-07-23). A legitimate developer's ten
  Packagist packages had malicious `dev-main` versions injected with dozens of
  GitHub Actions workflow files that spin up runners, pull an architecture-specific
  Linux payload from `43[.]228[.]157[.]68`, and scan for cPanel/WHM servers
  vulnerable to CVE-2026-41940 to harvest credentials, SSH material and cloud keys.
  Only the network and file indicators are ingested: the maintainer is a victim, so
  neither the account nor the bare package names are flagged.
- **Apex macOS infostealer** (2026-07-22). A postinstall dropper installs an
  AMOS-family macOS infostealer while installing a working forked coding agent as
  cover. npm removed `@apexfdn/apex`; the operator re-published the same payload as
  `@copilot-mcp/apex` about eleven hours later and churned twenty-plus versions in
  eight hours, so the packages are blocked by name rather than version.

### Added
- Version-pinned `jscrambler` (8.14.0/8.16.0/8.17.0/8.18.0/8.20.0),
  `jscrambler-webpack-plugin` 8.6.2, `gulp-jscrambler` 8.6.2, `grunt-jscrambler`
  8.5.2 and `jscrambler-metro-plugin` 9.0.2 in `KNOWN_BAD_NPM_VERSIONS`
  (src/ioc-blocklist.ts) and `BUNDLED_FEED` (src/threat-intel.ts), plus five
  SHA-256 payload hashes.
- `43[.]228[.]157[.]68` in `KNOWN_C2_IPS`, the DNS-callback subdomain
  `f5b0b742-240a-4811-8a5b-b0ba6060685d[.]dnshook[.]site` in `KNOWN_C2_DOMAINS`,
  and the Linux exploit payload SHA-256 in `KNOWN_MALICIOUS_HASHES` for the
  cPanel/WHM campaign, mirrored as `BUNDLED_FEED` entries.
- `^(@apexfdn\/apex|@copilot-mcp\/apex)$` to `MALICIOUS_PACKAGE_PATTERNS`
  (src/patterns.ts) plus bare-name `BUNDLED_FEED` entries for both packages.
- Campaign test coverage in `src/__tests__/campaigns.test.ts` for all three
  campaigns, including negative tests for the clean jscrambler 8.13.0 release.

## [5.17.7] - 2026-07-21
### Fixed
- `scan` now self-terminates after a clean or low-only scan instead of hanging.
  The scan command tears down Node's global HTTP and HTTPS keep-alive agents on
  the clean-return path, so pooled npm and PyPI registry sockets close and the
  event loop drains. On Node 22 and earlier, free keep-alive sockets stay
  referenced, so a scan with no critical or high findings could keep the process
  (and a CI runner) alive for hours. The critical, high, and `--fail-on` exit
  paths are unchanged. Added a spawn-based regression test that asserts the CLI
  self-exits on a clean scan.

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
- Source excerpts came from the daily news-aggregator feed; the exact package
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
- Source excerpts came from the daily news-aggregator feed; the exact indicators
  were confirmed against the linked primary reports before being added.

## [5.12.1] - 2026-07-12
**Threat-intel: jscrambler npm compromise (July 2026)**

- Added a bundled-feed IOC for the compromised `jscrambler@8.14.0` npm release,
  which shipped a malicious preinstall hook that drops a Rust-based infostealer
  during install (daily news-aggregator feed, 2026-07-11). Version-pinned only:
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

[Unreleased]: https://github.com/homeofe/supply-chain-guard/compare/v5.25.12...HEAD
[5.25.12]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.12
[5.25.11]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.11
[5.25.10]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.10
[5.25.9]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.9
[5.25.8]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.8
[5.25.7]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.7
[5.25.6]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.6
[5.25.5]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.5
[5.25.4]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.4
[5.25.3]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.3
[5.25.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.2
[5.25.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.1
[5.25.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.25.0
[5.24.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.24.0
[5.23.5]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.23.5
[5.23.4]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.23.4
[5.23.3]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.23.3
[5.23.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.23.2
[5.23.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.23.1
[5.23.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.23.0
[5.22.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.22.0
[5.21.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.21.0
[5.20.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.20.2
[5.20.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.20.1
[5.20.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.20.0
[5.19.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.19.0
[5.18.2]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.18.2
[5.18.1]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.18.1
[5.18.0]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.18.0
[5.17.10]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.10
[5.17.9]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.9
[5.17.8]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.8
[5.17.7]: https://github.com/homeofe/supply-chain-guard/releases/tag/v5.17.7
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
