# Node.js support policy

This file is the single authoritative statement of which Node versions this project
supports, tests, publishes from and develops against. It is not a description of the
configuration. `src/__tests__/node-version-contract.test.ts` parses the block below
and fails the build if any declaration site in the repository disagrees with it.
Change the policy here and the gate names every file that has to follow.

## The policy

```json
{
  "baseline": 22,
  "enginesFloor": "22.0.0",
  "supportedMajors": [22],
  "transitionMajors": [20],
  "transitionRemovedIn": "5.29.0",
  "publishMajor": 22,
  "runtimeMajor": 22,
  "devBaseline": 22
}
```

| field | meaning | where it must appear |
| --- | --- | --- |
| `baseline` | the canonical target platform | this document, and every field below |
| `enginesFloor` | the lowest Node a consumer is supported on | `engines.node` in `package.json` |
| `supportedMajors` | majors that are supported and fully tested | the `compat` matrix in `ci.yml` |
| `transitionMajors` | majors still verified but NO LONGER SUPPORTED | the `compat` matrix in `ci.yml` |
| `transitionRemovedIn` | the release that deletes the transition lane | asserted against `package.json` version |
| `publishMajor` | the major the npm artifact is published from | the `publish` job in `ci.yml` |
| `runtimeMajor` | the major the published Action and image execute on | `action.yml`, `Dockerfile` |
| `devBaseline` | what a contributor should develop on | `.devcontainer/devcontainer.json` |

## Supported is not the same as tested

This distinction is the whole point of the current arrangement, and the gate enforces
it in both directions.

- A **supported** major is one this project promises to work on. It is at or above
  `enginesFloor`, it runs the complete suite, and a consumer on it can file a bug.
- A **transition** major is one that still runs the complete suite but is **below the
  floor and out of support**. It exists so that anyone who has not migrated yet finds
  out from a warning rather than from a breakage, and it is deleted on a fixed date.

The gate asserts every supported major is at or above the floor, and every transition
major is strictly **below** it. A major cannot be in both lists. If a transition major
were allowed at or above the floor it would be indistinguishable from a supported one,
which is how "temporary" support becomes permanent.

## Node 20 is a transition lane, not a baseline

Node 20 reached end of life on **2026-04-30**, confirmed against the upstream
`nodejs/Release` schedule rather than from memory. It receives no security patches.
Node 22 is supported until 2027-04-30.

For a tool whose entire purpose is supply-chain security, treating an unpatched
runtime as the strategic baseline is a defect in the product, not a housekeeping
detail. As of v5.28.0 Node 22 is the canonical baseline everywhere: `engines.node`,
the publish job, the composite Action, the container image and the dev container all
declare it, so there is no longer a state where the documentation says one thing, CI
tests another, publishing uses a third and distribution executes a fourth.

`engines.node` is now `>=22.0.0`. npm reports an engine mismatch as **EBADENGINE, a
warning, not an error**, unless the consumer sets `engine-strict=true`. So a consumer
still on Node 20 is warned rather than broken, which is exactly what a transition
period is for.

## The removal milestone, and why it cannot be forgotten

**The Node 20 transition lane is deleted in v5.29.0.**

That is not a note in a document that someone has to remember to act on. The gate
compares `transitionRemovedIn` against the version in `package.json` and **fails the
build** once the project reaches or passes that version while `transitionMajors` is
still non-empty. The transition therefore cannot outlive its own milestone: the
release that would carry it past the deadline cannot be built until the lane is
removed.

To perform the removal:

1. Set `transitionMajors` to `[]` and delete `transitionRemovedIn` from the block.
2. Run the build. The gate names every file that still refers to Node 20.
3. Remove the `20` entry from the `compat` matrix in `ci.yml`.

To extend the deadline instead, `transitionRemovedIn` has to be edited deliberately,
in a diff someone reviews, with a reason. That is the difference between a decision
and a drift.

## Two invariants that were being violated

Both are asserted, and both were false before this policy existed:

- **`runtimeMajor` must be a supported major.** The published Action and the published
  container image both ran on Node 22 while CI built and tested only on Node 20, so the
  two most-used distribution channels executed on a major that nothing verified.
- **`publishMajor` must be a supported major.** An artifact must not be built by a
  toolchain the suite has never run under. Until v5.28.0 the npm artifact was published
  from Node 20, a third runtime distinct from both the tested one and the executed one.

## The npm pin on the publish job

The publish job used to pin `npm@11.18.0` explicitly, because npm 12 requires Node
`>=22` and hard-failed EBADENGINE on the Node 20 runner, which broke the v5.11.0
publish on 2026-07-09. That constraint is a consequence of Node 20 and disappears with
it. See `.github/workflows/ci.yml` for what the pin is now and why; it is still an
exact pinned version rather than `@latest`, because a publish lane that resolves a
floating version is a publish lane whose behaviour changes without a commit.

## What is deliberately not governed here

Threat intelligence and test fixtures mention Node versions as data, not as policy: a
Dockerfile fixture pinned to `node:20-alpine` exists precisely to be scanned, and the
advice string in the Dockerfile scanner names a version because it is example output.
The gate excludes `src/`, test fixtures, `CHANGELOG.md` and `.ai/handoff/` for that
reason, and the exclusion list in the test names each one with its reason.
