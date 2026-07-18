# supply-chain-guard - Architecture

> This file describes the STABLE architecture (conventions, data flow, design
> principles). The volatile parts - the exact module list and counts - are NOT
> duplicated here (that is how this file drifted for months describing a
> `src/detectors/` layout that no longer exists). The live inventory is in the
> generated **DASHBOARD.md** ("Source Modules"), and the naming convention is in
> **CONVENTIONS.md** ("Module Structure").

## Module Layout (convention, not a list)

Flat, one file per scanner/detector directly under `src/` - there is no
`detectors/` subdirectory. Each ecosystem or surface has its own
`src/<name>-scanner.ts` (e.g. `npm-scanner.ts`, `pypi-scanner.ts`,
`cargo-scanner.ts`, `github-actions-scanner.ts`, `agentic-workflow-scanner.ts`),
with shared pieces in `patterns.ts`, `types.ts`, `reporter.ts`, and the CLI in
`cli.ts`. Tests mirror sources one-to-one in `src/__tests__/<module>.test.ts`.
For the current module and test-file counts, see DASHBOARD.md (gate-kept fresh).

## Data Flow

1. `cli.ts` (commander) parses the sub-command (`scan` / `npm` / `feed` / `mcp` / ...).
2. `scanner.ts` is the orchestrator: it decides which sub-scanners apply to the
   target and, for a self-scan, suppresses the tool's own IOC/threat-intel data
   (own-repo recognition) while still running the malware/obfuscation patterns.
3. Each sub-scanner runs its detection rules (each with a unique `rule` ID) over
   the relevant files/manifests and returns findings.
4. `correlation-engine.ts` links related findings into incident-level attack
   chains; `risk-engine.ts` and `trust-breakdown.ts` compute the scores.
5. `reporter.ts` formats output (text, JSON, SARIF, CycloneDX SBOM, JUnit, etc.).

## Key Design Decisions

- **One runtime dependency** (`commander`); everything else is Node built-ins, so
  the scanner installs clean and has minimal supply-chain surface of its own.
- **Deterministic, offline gates**: the prebuild checks (changelog, version-sync,
  handoff, feed, claims) and the generated handoff docs are pure functions of
  committed files - no timestamps, no network - so they cannot silently drift.
- **Conservative detection**: typosquat/starjacking/self-scan paths favour
  avoiding false positives (whitelists, related-name and monorepo guards).
- **Threat intel is data, not code**: IOCs live in `threat-intel.ts` /
  `ioc-blocklist.ts` and the published `feed.json`, versioned with the release.
- **SARIF + SBOM** for GitHub Security tab and supply-chain inventory integration.
