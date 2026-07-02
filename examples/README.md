# Examples

Ready-to-copy CI recipes for supply-chain-guard. Each file is a complete,
minimal configuration - copy it into your repository and adjust the few
marked values.

## Recipes

| File | What it does |
| --- | --- |
| [`github-action-basic.yml`](github-action-basic.yml) | Minimal GitHub Actions workflow using the published Action (`homeofe/supply-chain-guard@v5`). Scans on every push and PR, fails on high severity findings, posts results as a PR comment. |
| [`bot-pr-gate.yml`](bot-pr-gate.yml) | Gate for bot PRs (Dependabot / Renovate). Runs only when a bot opens the PR, diff-scans just the files changed against `origin/main`, and blocks auto-merge if the updated dependency tree trips malware indicators. |
| [`gitlab-ci.yml`](gitlab-ci.yml) | GitLab CI job template. Installs the CLI, scans with JSON output, fails on high severity, and uploads the report as a job artifact. |
| [`circleci-config.yml`](circleci-config.yml) | CircleCI job on `cimg/node`. Installs the CLI, scans with JSON output, fails on high severity, and stores the report as a build artifact. |
| [`Jenkinsfile`](Jenkinsfile) | Jenkins declarative pipeline stage in a `node:20` Docker agent. Installs the CLI, scans with JSON output, fails on high severity, and archives the report via `archiveArtifacts`. |
| [`azure-pipelines.yml`](azure-pipelines.yml) | Azure Pipelines job on `ubuntu-latest`. Installs Node 20 via `NodeTool@0`, scans with JSON output, fails on high severity, and publishes the report via `PublishBuildArtifacts@1`. |

## Why the bot PR gate matters

Automated dependency-update PRs with auto-merge enabled are a prime
supply-chain attack path: a malicious patch release gets published, the bot
opens a PR within hours, and auto-merge lands it before any human looks at
it. Putting a scanner in the required-checks path means the bot PR cannot
merge while the diff contains known malware indicators.

## Contributing more recipes

We would love recipes for additional CI systems (check the issue tracker
for open `help wanted` issues). To contribute:

1. Add a new file here following the naming pattern `<system>-<purpose>.yml`
2. Keep it minimal: one job, sensible defaults, comments on the lines users
   will want to change
3. Add a row to the table above
4. Open a PR - see [CONTRIBUTING.md](../CONTRIBUTING.md)
