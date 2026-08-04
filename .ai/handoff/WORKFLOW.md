# supply-chain-guard: Autonomous Multi-Agent Workflow

> Based on the [AAHP Protocol](https://github.com/homeofe/AAHP).
> Agents orient from MANIFEST.json first. Model and role routing are owned by the
> active harness, not by this repository.

---

## Authority and Roles

MANIFEST.json tasks is the authoritative machine-readable task graph.
It records task state, dependencies, and priority. NEXT_ACTIONS.md is the concise
human-readable view of open work. DASHBOARD.md is generated and display-only.

| Role | Responsibility |
|------|----------------|
| Implementer | Code, focused tests, refactoring, and implementation notes |
| Reviewer | Independent correctness, edge-case, and security review |
| Researcher | Primary-source research for vulnerabilities, campaigns, and specifications |

The harness may assign any suitable model or agent to these roles.

---

## The Pipeline

### Phase 1: Pick a Task

    Reads:   MANIFEST.json quick_context and tasks
             STATUS.md for the current project snapshot
             NEXT_ACTIONS.md for concise acceptance context
             CONVENTIONS.md for repository rules

    Does:    Filters tasks with status ready
             Requires every depends_on task to be done
             Sorts eligible work critical > high > medium > low
             Marks the selected task in_progress and records the assignee
             Reads the task's canonical Acceptance criteria before implementation

If MANIFEST.json has no task graph, use NEXT_ACTIONS.md temporarily and add the
missing task graph during the handoff update.

### Phase 2: Implement

    Reads:   Relevant source and test files
             Existing patterns, fixtures, and project-specific guidance

    Does:    Implements code and tests
             Runs focused tests on the local machine
             Runs npm run build
             Uses Linux CI for the authoritative full-suite result

Do not run the full suite on Windows solely to reproduce the known missing-zip
failures in VS Code archive tests.

### Phase 3: Review and Verify

    Does:    Reviews the diff for correctness and security boundaries
             Runs focused regression tests for every changed behavior
             Runs AAHP lint, doctor, and the appropriate verify level
             Records limitations as assumed or unknown instead of overstating them

### Phase 4: Update Handoff

    Updates: STATUS.md as one current-state snapshot, replacing stale facts
             MANIFEST.json tasks and dependencies
             NEXT_ACTIONS.md when the open backlog changed
             Resolves each acceptance box with evidence, an explicit waiver,
               or a linked open follow-up before marking a task done
             Sets a completed task to done with its completion timestamp and
               records closure evidence in Recently Completed Resolution
             Re-evaluates dependency-blocked tasks and marks newly eligible
               tasks ready when every depends_on task is done

    Runs:    npm run handoff:refresh
             bash scripts/aahp-manifest.sh . --agent <id> --phase <phase>
               --context "<accurate concise state>"

DASHBOARD.md, TRUST.md, LOG.md, and MANIFEST.json file metadata are generated.
Never hand-edit DASHBOARD.md, TRUST.md, or LOG.md. History belongs in CHANGELOG.md,
the generated LOG.md, LOG-ARCHIVE.md, and git history, not appended STATUS notes.

### Phase 4.5: Optional Grounding Audit

Run a focused grounding audit before Phase 5 for security-sensitive,
agent-governance, compliance, or otherwise high-impact work. GROUNDING.md defines
the provenance levels, required external anchors, and challenge scope.

The audit is advisory and evaluates trust of claims, not general code style. It
returns exactly one verdict:

- SHIP: claims are adequately anchored.
- NEEDS_CHANGES: specific claims or evidence need repair.
- BLOCK: an ungrounded high-impact claim makes handoff or release unsafe.

Resolve a BLOCK by fixing the evidence or reclassifying the claim; do not hand off
while BLOCK stands. Resolve NEEDS_CHANGES findings or record an explicit owner
decision before final handoff.

### Phase 5: Handoff or Release

For ordinary work, hand off the verified diff and the exact Linux-only checks still
required. For version-bump work, follow the repository-root CLAUDE.md ceremony:

1. Add the Keep a Changelog release block and matching reference link.
2. Bump every version site governed by aahp.config.json.
3. Refresh package-lock.json, the handoff set, and MANIFEST.json.
4. Open a PR against protected main and wait for Build and Test plus AAHP Verify.
5. Squash-merge, pull main, and tag that exact merged commit.
6. Push only the immutable semver tag. CI performs OIDC npm publishing, creates
   the GitHub Release, and fast-forwards the v5 branch.

---

## Pipeline Rules

- MANIFEST.json tasks is authoritative; DASHBOARD.md is display-only.
- Acceptance criteria use one canonical task-box section per implementation
  task. `aahp criteria` is advisory; reviewers verify the evidence.
- A blocked task is skipped. If all tasks are blocked, notify the project owner.
- Notify the owner on a completed task or a real blocker, not routine phase changes.
- Main is protected with admin enforcement. All changes land through a PR and
  required Build and Test plus AAHP Verify checks.
- Each commit must build and every changed behavior needs focused positive and
  negative regression coverage.
- Never weaken a security gate merely to make a local environment green.

---

## Working with the Codebase

### Adding a scanner module

1. Create src/<platform>-scanner.ts.
2. Export a typed scan entry point.
3. Wire it into src/scanner.ts.
4. Add focused tests under src/__tests__/.
5. Run npm run handoff:refresh so the generated component inventory updates.
6. Update user-facing documentation when behavior or configuration changed.

### Adding detection rules

1. Put shared signatures in src/patterns.ts or keep platform-specific logic local.
2. Use a unique SCREAMING_SNAKE_CASE rule ID with the appropriate category prefix.
3. Add a positive regression and a false-positive regression.
4. Document user-visible rules or configuration.

### Bumping a version

Use CLAUDE.md as the authority. All configured version sites, CHANGELOG.md,
STATUS.md, NEXT_ACTIONS.md, generated handoff files, and MANIFEST.json must agree.

---

## Context Budget

| Load | Files |
|------|-------|
| Minimal | MANIFEST.json |
| Normal | MANIFEST.json, STATUS.md, NEXT_ACTIONS.md, CONVENTIONS.md |
| Full | All canonical handoff files |
| Deep dive | Handoff plus the relevant source and tests |

Start with the smallest trustworthy context and load more only as needed.
