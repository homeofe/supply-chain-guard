# Node.js support policy

This file is the single authoritative statement of which Node versions this
project supports, tests, publishes from and develops against. It is not a
description of the configuration: `src/__tests__/node-version-contract.test.ts`
parses the block below and fails the build if any declaration site in the
repository disagrees with it. Change the policy here and the gate will tell you
every file that has to follow.

## The policy

```json
{
  "enginesFloor": "20.0.0",
  "testedMajors": [20, 22],
  "publishMajor": 20,
  "runtimeMajor": 22,
  "devBaseline": 22
}
```

| field | meaning | where it must appear |
| --- | --- | --- |
| `enginesFloor` | the lowest Node a consumer may install on | `engines.node` in `package.json` |
| `testedMajors` | every major the complete build and suite runs on | the `compat` matrix in `ci.yml` |
| `publishMajor` | the major the npm artifact is published from | the `publish` job in `ci.yml` |
| `runtimeMajor` | the major the published Action and image execute on | `action.yml`, `Dockerfile` |
| `devBaseline` | what a contributor should develop on | `.devcontainer/devcontainer.json` |

Two invariants make the rest of it hold, and both are asserted:

- **`runtimeMajor` must be in `testedMajors`.** This one was violated. Until
  this policy existed, the published Action and the published container image
  both ran on Node 22 while CI built and tested only on Node 20, so the two
  most-used distribution channels executed on a major that nothing verified.
- **`publishMajor` must be in `testedMajors`.** An artifact must not be built by
  a toolchain the suite has never run under.

## Why 22 and not only 20

Node 20 reached end of life on 2026-04-30, confirmed against the upstream
`nodejs/Release` schedule rather than from memory. It receives no further
security patches. Node 22 is supported until 2027-04-30.

For a tool whose entire purpose is supply-chain security, building and shipping
from an unpatched runtime is a defect in the product, not a housekeeping detail.

## Why the floor is still 20

Raising `engines.node` is a promise broken for every consumer still on Node 20,
and this project is installed inside other people's CI where the Node version is
often not theirs to choose. The floor moves only once the evidence is in, and the
evidence is the point of the current arrangement: the complete suite, the
governance gates and a clean-room install of the packed tarball all run on both
majors, every commit.

## The one exception, and how it ends

**Exception: the npm publish job still runs on Node 20 (`publishMajor: 20`).**

- **Why.** The publish job is the only lane that cannot be rehearsed. It runs
  solely on a semver tag push, it authenticates by OIDC against the npm Trusted
  Publisher, and OIDC cannot be exercised by a dry run. A failed publish cannot
  be retried on the same version, because tags here are immutable, so the cost of
  being wrong is a burned version number. It has been paid before: npm 12 dropped
  Node 20, `npm@latest` hard-failed EBADENGINE, and the v5.11.0 publish broke.
- **What reduces the risk meanwhile.** Everything upstream of the OIDC call is
  now proven on Node 22 every commit, because `scripts/validate-package.sh` packs
  the tarball, inspects its contents against the manifest, installs it into a
  clean directory and runs the CLI and the programmatic entry point from that
  install, on both majors.
- **Owner.** The repository maintainer.
- **Exit condition, mechanically checkable.** Set `publishMajor` to 22 in the
  block above and delete this section. The gate then requires the `publish` job
  in `ci.yml` to declare Node 22, and requires 22 to be in `testedMajors`. The
  condition for doing so is that the packaged-artifact lane has been green on
  `main` on the Node 22 leg across at least one release cycle, which is visible
  in the Actions history for the `compat (Node 22)` job.
- **Tracked in.** `.ai/handoff/NEXT_ACTIONS.md`, not a GitHub issue. This
  repository holds zero open issues by rule, so an issue is not a durable place
  to track anything here.

## Moving the floor to 22 later

The migration is mechanical once the decision is made, and the gate drives it:

1. Set `enginesFloor` to `22.0.0` and `testedMajors` to `[22, 24]` here.
2. Run the build. The drift gate names every file that still says 20, including
   the user-facing examples, which are asserted to reference only tested majors
   precisely so that they cannot be forgotten.
3. Update `engines.node`, the matrix and whatever else the gate listed.
4. Ship it as a minor at least, and say so in the changelog: for a consumer
   pinned to Node 20 this changes whether the package installs cleanly.

## What is deliberately not governed here

Threat intelligence and test fixtures mention Node versions as data, not as
policy: a Dockerfile fixture pinned to `node:20-alpine` exists to be scanned, and
the advice string in the Dockerfile scanner names a version because it is example
output. The gate excludes `src/`, test fixtures and `CHANGELOG.md` for that
reason, and the exclusion list in the test names each one with its reason.
