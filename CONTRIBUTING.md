# Contributing to supply-chain-guard

Thanks for your interest in contributing! This project aims to make supply-chain security accessible to everyone.

## Development and review

supply-chain-guard is developed with AI assistance under maintainer review. Every change is reviewed and tested before it ships, detection changes go through an adversarial review pass, and every release commit is cryptographically signed by the maintainer (GitHub "Verified"). The maintainer is accountable for what lands in a release.

## How to Contribute

### Reporting New Malware Patterns

The most valuable contribution is adding new detection patterns. If you discover a new supply-chain attack or malware campaign:

1. Open an issue with the `new-pattern` label
2. Include IOCs (indicators of compromise) if available
3. Reference any public reports or advisories

### Adding Detection Rules

1. Fork the repository
2. Add patterns to `src/patterns.ts` (or the relevant scanner module)
3. Add tests for your new patterns
4. Submit a pull request

Each pattern needs:
- A unique rule ID (e.g., `CATEGORY_DESCRIPTION`)
- A regex pattern
- A description
- A severity level (critical/high/medium/low/info)
- Test coverage (positive + negative cases)

### Adding Correlation Rules

The correlation engine (`src/correlation-engine.ts`) links individual findings into incident clusters. To add a new correlation:

1. Identify 2-3+ rules that together indicate a specific attack chain
2. Add an entry to the `CORRELATION_RULES` array
3. Include an incident name, severity, confidence boost, and narrative
4. Add a test case in `src/__tests__/correlation-engine.test.ts`

### Adding IOCs to the Blocklist

Known indicators of compromise go in `src/ioc-blocklist.ts`:
- C2 domains and IPs
- Malware file hashes (MD5)
- Malicious GitHub accounts
- Compromised npm/PyPI package versions

### Code Contributions

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `npm test`
5. Run type check: `npm run lint`
6. Commit with a clear message, and **no AI or tool attribution** (see below)
7. Push and open a PR

### No AI or tool attribution

The project is developed with AI assistance, but the **author of record is the
human**. Two required CI checks enforce this between them: `Build and Test`
covers the **commit messages and the author/committer identity** across the pull
request's commit range, and `PR metadata policy` covers the **PR title and body**.
They are separate because their inputs are: a title edit cannot change code, so it
must not trigger a full build. Either one fails a pull request carrying tool or
model attribution: a "Generated with ..." footer, a `Co-authored-by:` (or
`Assisted-by:` / `Generated-by:`) trailer naming an AI, or an AI vendor no-reply
address. The same rule is gated over the published files (`CHANGELOG.md`,
`README.md`, `docs/`, `package.json`, `server.json`, and the rest of the npm
payload), because `CHANGELOG.md` becomes the GitHub Release body and is indexed
permanently.

Two deliberate carve-outs:

- Matching is anchored on attribution **phrasing**, not on vendor names, so this
  repository's own threat intelligence about AI-branded malware (for example a
  "Claude Code leak campaign" indicator) is unaffected.
- `.ai/handoff/**` is out of scope. That is where an agent note is expected to
  record which model did the work.

If a revert or cherry-pick inherits a trailer from an older commit, the check
skips it: you are not asked to rewrite history you did not author.

### Benchmark evidence carries counts, never consumer names

Measuring a rule change against real repositories is the strongest evidence a
pull request here can carry, and you are encouraged to do it. Report it as
**counts and classes only**:

> Measured against the released v5.17.9 binary on **seven consumer
> repositories**: 128 -> 92 findings, 10 -> 1 criticals.

Never list the repositories by name. This project is a scanner, so its own
measurements are read as a finding inventory: a list of names next to
"10 criticals" tells a stranger which specific codebases hold unfixed critical
issues, and which of them are private. The counts alone prove exactly the same
thing about the rule change, which is the claim you are actually making.

The same applies to naming one repository as the source of an attack shape
("the `<name>` pattern") in a rule comment or a test. Describe the shape, not
the codebase you found it in.

This is not only about files. It applies with **full force to the pull request
body and title**, and to anything that reaches a release body, because those are
indexed and a later commit cannot retract them. `CHANGELOG.md` becomes the
GitHub Release body verbatim.

A `consumer-repo-disclosure` gate in `aahp.config.json` fails the build on the
`<org>/<repo>` and `<org>-<name>` reference shapes across the published files,
the source tree and the handoff notes. Read its `message` field before working
around it: it deliberately does **not** carry a list of private repository
names, because that list, in a public config file, would itself be the
disclosure it exists to prevent. A consumer named without that prefix will not
trip it, so the rule above is the real control and the gate is the backstop.

That gate reads **files**. A pull request title and body are not files, so it
has never been able to see them - and they are the surface you cannot take back,
because a merged body stays indexed for good. The `PR metadata policy` required
check therefore carries a second copy of the same pattern, reading the title and
body from the event payload. The two copies are deliberately under **different**
required check names, so neither one going green for its own reasons can stand
in for the other, and `workflow-trigger-contract.test.ts` asserts they are
byte-identical twins.

### Code Style

- TypeScript strict mode
- No `any` types (use `unknown` and type guards)
- Keep functions focused and testable
- Add JSDoc comments for public APIs
- New findings should include `confidence` and `category` fields (v4.2+)

### Testing

- All new features need tests
- All new patterns need test cases (both positive and negative)
- False-positive tests are valuable (ensure legitimate code isn't flagged)
- Run `npm test` before submitting

### Project Structure

```
src/
  scanner.ts              # Core orchestration
  pattern-scanner.ts      # Bounded per-file pattern scan orchestration
  pattern-applicability.ts # File-type and path applicability rules
  broad-gap-pattern-matchers.ts # Structural matchers for broad-gap rules
  correlated-pattern-matchers.ts # Correlated multi-signal matchers
  workflow-pattern-matchers.ts # Structural GitHub Actions matchers
  regex-complexity.ts     # Regex safety and complexity validation
  patterns.ts             # Detection pattern database
  extracted-file-walker.ts # Containment-aware extracted-tree traversal
  remote-download.ts      # Bounded HTTPS registry artifact downloads
  ioc-blocklist.ts        # Known IOC database
  correlation-engine.ts   # Incident clustering
  trust-breakdown.ts      # Trust scoring
  install-hook-scanner.ts # Install script analysis
  dependency-risk-analyzer.ts  # Typosquatting detection
  publishing-anomaly-detector.ts  # npm publish anomalies
  release-scanner.ts      # GitHub release analysis
  github-trust-scanner.ts # Repo trust signals
  github-actions-scanner.ts  # CI/CD attack detection
  agentic-workflow-scanner.ts # GitHub Agentic Workflow (gh-aw) markdown posture (GitLost class)
  dockerfile-scanner.ts   # Container security
  npm-scanner.ts          # npm package analysis
  pypi-scanner.ts         # PyPI package analysis
  cargo-scanner.ts        # Rust/Cargo analysis (Cargo.toml/Cargo.lock/build.rs)
  go-scanner.ts           # Go module analysis (go.mod/go.sum)
  python-lockfile-scanner.ts # Python lockfiles (poetry.lock/uv.lock/Pipfile.lock)
  rubygems-scanner.ts     # RubyGems (Gemfile/Gemfile.lock) analysis
  composer-scanner.ts     # Composer/PHP (composer.json/composer.lock) analysis
  nuget-scanner.ts        # NuGet/.NET (packages.lock.json/csproj/nuget.config) analysis
  skills-scanner.ts       # AI agent skill/rules files (.claude, .cursorrules, CLAUDE.md)
  openclaw-plugin-scanner.ts # OpenClaw plugin manifest posture (openclaw.plugin.json)
  mcp-scanner.ts          # MCP server config analysis (.mcp.json, claude_desktop_config.json)
  mcp-server.ts           # Zero-dep MCP server (supply-chain-guard mcp)
  entropy.ts              # Shannon entropy analysis
  lockfile-checker.ts     # Lockfile integrity
  config-scanner.ts       # Package manager configs
  git-scanner.ts          # Git hooks/submodules
  policy-engine.ts        # Policy config, baseline, suppressions
  trust-signals.ts        # Positive trust indicators
  threat-intel.ts         # External IOC feed integration
  feed.ts                 # Feed stats + published-feed refresh (feed.json channel)
  risk-engine.ts          # Multi-dimensional risk scoring
  diff-scanner.ts         # Git diff-based incremental scanning
  org-scanner.ts          # Organization-level scanning
  remediation-engine.ts   # Automated fix suggestions
  playbooks.ts            # Incident response playbooks
  dependency-governance.ts # Dependency policies
  soc-exporter.ts         # SIEM/SOC export formats
  attack-graph.ts         # Attack path modeling
  active-validation.ts    # Confidence tiers & validation
  workflow-modeler.ts     # GitHub Actions chain modeling
  workflow-ast.ts         # Zero-dep workflow parser (triggers/permissions/steps)
  workflow-graph.ts       # Cross-workflow trust-boundary analysis (Cordyceps)
  secret-simulator.ts     # Honeytoken system
  posture-engine.ts       # Org-wide risk posture
  continuous-monitor.ts   # Risk history & trend tracking
  triage-engine.ts        # Finding ownership & triage
  sla-engine.ts           # Remediation SLA tracking
  risk-forecast.ts        # Risk trajectory prediction
  metrics.ts              # Security KPIs & metrics
  reporter.ts             # Output formatting
  osv-export.ts           # OSV-schema export of malicious-package IOCs
  cli.ts                  # CLI entry point
  types.ts                # TypeScript interfaces
  __tests__/              # Test files
```

## CI gates and required checks

A pull request is judged on three required status checks, and admins are not
exempt from them:

| check | produced by | what it means |
| --- | --- | --- |
| `Build and Test` | `ci.yml` | every supported Node major built, passed the full suite and installed from its own packed tarball, and the container image builds and scans |
| `aahp-verify` | `aahp-verify.yml` | the handoff state is intact and changed along with the code |
| `PR metadata policy` | `pr-metadata-policy.yml` | the PR title and body carry no tool or model attribution |

Two things about this surprise people:

- **`npm run build` is not just `tsc`.** It runs three governance gate groups
  first. A red gate is the task, not an obstacle to route around.
- **A code change must bring its handoff state with it.** `aahp-verify` enforces a
  content-drift gate: if code changed, `.ai/handoff/STATUS.md` and `MANIFEST.json`
  must change too. Add a short entry to STATUS.md describing what you did and why,
  then run `npm run handoff:refresh` and commit the result. Only dependabot is
  exempt.

You can also validate the published artifact locally, exactly as CI does:

```bash
bash scripts/validate-package.sh
```

It packs the tarball, installs it into a throwaway directory and drives the CLI
from that install. On Windows set `SCG_VALIDATE_TMP` to an explicit native path
first, because MSYS and native node disagree about where `/tmp` is.

Full detail on what runs when, how branch protection behaves and how a release is
cut: [`docs/ci-and-release.md`](docs/ci-and-release.md). Node version policy:
[`docs/node-support.md`](docs/node-support.md).

## Development Setup

```bash
git clone https://github.com/homeofe/supply-chain-guard.git
cd supply-chain-guard
npm install
npm run build
npm test
```

## Development Environments

### Dev container (recommended)

The repository ships a [dev container](.devcontainer/devcontainer.json). Open the
repo in VS Code and choose "Reopen in Container" (or use GitHub Codespaces) - it
installs Node 22, the `zip` CLI, and runs `npm ci` automatically. In the
container ALL tests pass, including the 14 vscode-scanner tests that need the
`zip` binary.

### Bare Windows checkout

On a bare Windows machine without a `zip` binary, 14 vscode-scanner tests fail
locally. This is NOT a regression - those tests build .vsix fixtures with `zip`
and are green in CI and in the dev container. Everything else runs fine on
Windows; use the dev container if you want a fully green suite locally.

## CI Recipes

Looking to integrate the scanner into your own pipeline? See
[`examples/`](examples/) for ready-to-copy recipes: a minimal GitHub Actions
workflow, a Dependabot/Renovate bot PR gate, and a GitLab CI job template.
Contributions for more CI systems are welcome.

## Questions?

Open an issue or reach out at emre.kohler@elvatis.com.
