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
  "supportedMajors": [22, 24],
  "transitionMajors": [],
  "activeLtsMajor": 24,
  "activeLtsReviewedIn": "6.1.0",
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
| `activeLtsMajor` | the upstream Active LTS major `supportedMajors` must reach | asserted against `supportedMajors` and the `compat` matrix |
| `activeLtsReviewedIn` | the release by which `activeLtsMajor` must be re-read from upstream | asserted against `package.json` version |
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

## The support claim has a top as well as a bottom

`engines.node` is a **floor with no ceiling**. `>=22.0.0` is a claim about Node 22 and
about every major after it, including majors that do not exist yet. Before the
`activeLtsMajor` field existed, the `compat` matrix stopped at 22, so the entire claim
above the floor was made and never executed. That is the same defect the floor half of
this policy exists to prevent, in the opposite direction: a statement about a runtime
with nothing behind it.

It was not hypothetical. Read against the upstream `nodejs/Release` schedule on
**2026-08-22**, Node 22 entered **Maintenance** LTS on 2025-10-21 and Node 24 has been
**Active** LTS since 2025-10-28. So the only major the project supported was the one
already in maintenance, and the major consumers are actively migrating onto was claimed
by `engines.node` and never run. The devDependency `@types/node` is on the Node 26 API
surface, so an API that exists only above Node 22 would type-check clean, pass every
leg of the matrix, and fail in a consumer's hands.

**The invariant, asserted by the gate:** `max(supportedMajors)` is at or above
`activeLtsMajor`, and at least one leg of the `compat` matrix is at or above it too.

### Why the bound is the Active LTS and not something else

The claim is unbounded, so it cannot be covered exhaustively; a bound has to be chosen
and stated. The choices considered, and why this one:

- **At or above the current Active LTS** (chosen). The Active LTS is the major that
  consumers are moving their CI and their production images onto, and it is the major a
  security tool is most likely to be invoked under for the next two years. It changes
  once a year, in October, so the matrix does not churn.
- **Every LTS major that is not end of life.** Rejected: it grows the matrix without
  adding a distinct runtime risk, since Maintenance LTS majors receive no new language
  or API surface. Note that the baseline major stays in the matrix on its own account,
  so a Maintenance LTS baseline is covered anyway.
- **Every major upstream currently ships, including the Current line.** Rejected: the
  Current line turns over every six months, so the matrix would need an edit twice a
  year to stay green, and a gate that has to be edited on a calendar is a gate people
  learn to edit without reading.

### The residual this leaves, stated rather than hidden

Majors above `activeLtsMajor` are claimed by `engines.node` and are **not executed**.
On 2026-08-22 that is Node 26, which is on the Current line and becomes LTS on
2026-10-28. A consumer running the package on a Current-line major is inside the
declared range and outside the tested range. That is a deliberate trade, not an
oversight.

The alternative, **not** chosen, and exactly what to change if a future maintainer
prefers it: give `engines.node` an upper bound, for example `>=22.0.0 <25.0.0`, and add
a gate case asserting the ceiling equals `max(supportedMajors) + 1`. That closes the
residual completely and costs a release every time a new major lands, plus an
`EBADENGINE` warning for every consumer who upgrades Node before this package cuts that
release. For a tool that is installed broadly and often run in someone else's CI, the
warning noise was judged worse than the untested Current line. Revisit that judgement if
this package ever starts using an API whose behaviour differs across majors.

### `activeLtsMajor` is a fact from upstream, and it goes stale

The field is a **hand-copied constant, verified on 2026-08-22 against the
`nodejs/Release` schedule**. It is not derived at test time: a gate that resolves an
upstream fact over the network is a gate whose result depends on a stranger's uptime,
which is precisely the class of dependency this package exists to flag.

A hand-copied constant goes stale silently, so it carries a deadline in the same shape
as `transitionRemovedIn`: `activeLtsReviewedIn` is compared against the version in
`package.json`, and the gate **fails the build** once the project reaches that version.
Re-read the upstream schedule, correct `activeLtsMajor` if it moved, and move
`activeLtsReviewedIn` forward in a diff someone reviews.

The gate asserts `activeLtsMajor` is at or above `enginesFloor`, which catches the
value being dropped far enough to make the invariant vacuous, and catches a floor
raised above the Active LTS. It cannot catch a **wrong** value that is still at or
above the floor, because no assertion can check a hand-copied upstream fact without
going to the network. The deadline is the mitigation, and it is the only one.

Why `5.29.0` for that deadline: it is the next minor, it is the tightest value that
still lets the current release ship, and it is already the release that deletes the
Node 20 lane, so both Node policy chores land in the same review rather than in two.
The next upstream change is Node 26 entering LTS on **2026-10-28**, which is the fact
the reviewer will be checking for.

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

### Recorded decision: the leg below the floor stays until 5.29.0

A matrix leg below `engines.node` looks like a contradiction when `ci.yml` and
`package.json` are read side by side without this file, and it was reported as one in
https://github.com/homeofe/supply-chain-guard/issues/176. The decision, recorded here so
that the next reader meets it rather than re-derives it: **the Node 20 leg is not
removed early.**

- It does not claim support. `supportedMajors` and `transitionMajors` are disjoint
  lists, the gate asserts a transition major is strictly below the floor, and
  `README.md` tells consumers the package requires Node 22 or newer.
- Removing it early would delete the only evidence that a consumer who has not migrated
  can still install and run this package, one minor release before the milestone below
  deletes the lane anyway.
- The milestone is enforced by the build, not by memory, so the lane cannot outlive it.

What that report did surface, correctly, is that the matrix tested nothing **above** the
floor either. That half was a real gap and is fixed by `activeLtsMajor` above.

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

## Three invariants that were being violated

All three are asserted, and all three were false before the assertion existed:

- **`runtimeMajor` must be a supported major.** The published Action and the published
  container image both ran on Node 22 while CI built and tested only on Node 20, so the
  two most-used distribution channels executed on a major that nothing verified.
- **`publishMajor` must be a supported major.** An artifact must not be built by a
  toolchain the suite has never run under. Until v5.28.0 the npm artifact was published
  from Node 20, a third runtime distinct from both the tested one and the executed one.
- **`supportedMajors` must reach `activeLtsMajor`.** Before this field existed the matrix
  stopped at the floor, so `>=22.0.0` claimed Node 24 and Node 26 while neither ran,
  and the only supported major was one that had been in Maintenance LTS since
  2025-10-21.

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
