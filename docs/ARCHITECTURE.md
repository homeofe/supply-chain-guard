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
- **Deterministic, offline gates**: the prebuild gates (check:aahp, covering
  changelog presence and format, version sync, capability claims, forbidden
  patterns, schema-doc sync and doc links; plus check:feed and check:handoff) and the generated handoff docs are pure functions of
  committed files - no timestamps, no network - so they cannot silently drift.
- **Conservative detection**: typosquat/starjacking/self-scan paths favour
  avoiding false positives (whitelists, related-name and monorepo guards).
- **Threat intel is data, not code**: IOCs live in `threat-intel.ts` /
  `ioc-blocklist.ts` and the published `feed.json`, versioned with the release.
  Upstream discovery is a separate adapter pipeline with completeness-critical
  GitHub and OpenSSF sources; its trust boundaries and storage migration are in
  [feed-architecture.md](feed-architecture.md).
- **SARIF + SBOM** for GitHub Security tab and supply-chain inventory integration.

## Base Image Pinning (decision record)

`src/dockerfile-scanner.ts` parses every `FROM` instruction with one structural
matcher and sorts the reference into exactly one verdict. This section records
the two policy choices behind that, the options that were not taken, and why, so
that a later reader can revisit them on the same evidence rather than guess.

### Two tiers, not one

| Reference | Verdict | Rule | Severity |
|-----------|---------|------|----------|
| `FROM node:22-alpine@sha256:<64 hex>` | pinned | none | none |
| `FROM scratch` | reserved empty image | none | none |
| `FROM ubuntu` | no tag, no digest | `DOCKER_NO_TAG` | high |
| `FROM node:lts-alpine` | moving channel tag | `DOCKER_UNPINNED_BASE` | high |
| `FROM node:20-alpine` | tag, but no digest | `DOCKER_TAG_NOT_DIGEST` | low |

The option not taken was a single rule at `high` for every `FROM` line without a
digest. It was rejected on a measured consequence, not on taste: `high` is what
the DEFAULT gate fails on, because `getReportExitCode` in `src/reporter.ts`
returns exit 1 when `summary.high > 0`. One high tier would therefore flip every
ordinary version-tagged Dockerfile in every consumer from pass to fail in a
single release, for a risk that has not changed since the previous release.

The split follows the precedent this codebase already set for the same question
about GitHub Actions references: `src/github-actions-scanner.ts` reports a
branch-like ref as `GHA_UNPINNED_ACTION` (medium) and a version tag that is not a
commit SHA as `GHA_TAG_NOT_SHA` (low). `DOCKER_TAG_NOT_DIGEST` is the Docker
analogue of `GHA_TAG_NOT_SHA` and carries the same `low`.

What that costs, stated so nobody has to discover it: the default gate,
`--fail-on high` and `--fail-on medium` are unchanged by the new tier.
`--fail-on low`, `--fail-on info` and the risk score are not, because a `low`
finding weighs 1 point (`SEVERITY_WEIGHTS` in `src/risk-engine.ts`). A project
that wants the digest policy enforced raises its gate to `--fail-on low`. A
project that does not want the tier at all disables it in
`.supply-chain-guard.yml`:

```yaml
rules:
  disable: [DOCKER_TAG_NOT_DIGEST]
```

### Compose `image:` values are out of scope

`isDockerFile()` admits `docker-compose.yml` and `docker-compose.yaml`, so those
files are opened and read. Every rule in `DOCKERFILE_PATTERNS` is anchored on a
Dockerfile instruction keyword (`FROM`, `RUN`, `ADD`, `COPY`, `ENV`, `ARG`), and
none of them can match Compose syntax. A Compose file therefore returns nothing
from the Docker rule set, whatever it contains.

That is now said out loud in each `FROM` rule's `description`, in README.md and
here, because a file that is read by rules which structurally cannot match it
looks like coverage and is not.

The option not taken was an `image:` matcher scoped to `docker-compose.ya?ml`.
It was deferred rather than rejected, for one reason that needs solving first: in
Compose, a service that also declares `build:` uses `image:` to name the tag it
BUILDS, not an image it pulls. Reporting that as an unpinned base image would be
a false positive on a line the author cannot pin, and this project has one
runtime dependency and no YAML parser, so distinguishing the two cases means
tracking service-block structure by hand. A rule that fires on correct
configuration gets the whole tool switched off, which costs more than the gap it
closes. Anyone picking this up should start from that constraint.

### Stated bounds

- **`MAX_FROM_INSTRUCTION_CHARS = 1024`.** How much of one `FROM` instruction is
  parsed, and how much of a backslash-continuation chain is joined. It is
  roughly double the longest instruction the reference grammar can produce (an
  image name is capped at 255 characters, a tag at 128, a sha512 digest costs
  136 with its separator, `--platform=linux/arm64/v8` about 25), so no legal
  instruction reaches it. Its job is to keep the matcher linear on a single
  attacker-supplied multi-megabyte line and on a file of a million continuation
  lines. Beyond the bound an instruction produces no finding.
- **A digest counts as a pin only at full length**: `sha256` with 64 hex
  characters or `sha512` with 128, the two algorithms the OCI image
  specification registers. A truncated placeholder such as `@sha256:abc...`
  identifies no image and the daemon rejects it, so reading it as pinned would
  report a broken reference as safe.
- **A reference that is WHOLLY a variable** (`FROM $BASE`, `FROM ${BASE}`)
  produces no finding in either direction. Its value is not visible to a
  file-local scan and may itself carry a digest. The `ARG` default in the same
  file is deliberately not resolved, because `--build-arg` overrides it at build
  time, so the default is not authoritative.
- **Build stages are resolved in file order**, matching the daemon: a reference
  is treated as a stage only when an earlier `FROM ... AS <name>` declared it.
  A forward reference is not a stage and is still classified.
