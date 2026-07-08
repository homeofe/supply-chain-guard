import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { scanGitHubActionsWorkflows } from "../github-actions-scanner.js";

/**
 * GitLost-class agent-workflow posture rules (v5.10). Workflow bodies use
 * escaped \${{ ... }} so template-literal interpolation does not eat the GitHub
 * expression syntax.
 */
function writeWf(dir: string, name: string, content: string): void {
  const wfDir = path.join(dir, ".github", "workflows");
  fs.mkdirSync(wfDir, { recursive: true });
  fs.writeFileSync(path.join(wfDir, name), content);
}

describe("GitLost-class agent-workflow rules", () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-agent-")); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  const GITLOST_WF = `
name: issue-triage
on:
  issues:
    types: [assigned]
permissions:
  contents: read
  issues: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          GH_TOKEN: \${{ secrets.ORG_PAT }}
        with:
          github_token: \${{ secrets.ORG_PAT }}
          prompt: |
            A colleague asks: \${{ github.event.issue.body }}
`;

  it("flags an agent step reading untrusted issue context as GHA_AGENT_UNTRUSTED_PROMPT (critical)", () => {
    writeWf(tmp, "triage.yml", GITLOST_WF);
    const f = scanGitHubActionsWorkflows(tmp).find((x) => x.rule === "GHA_AGENT_UNTRUSTED_PROMPT");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("critical");
  });

  it("flags the public-post exfil channel as GHA_AGENT_PUBLIC_POST (high)", () => {
    writeWf(tmp, "triage.yml", GITLOST_WF);
    const f = scanGitHubActionsWorkflows(tmp).find((x) => x.rule === "GHA_AGENT_PUBLIC_POST");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("high");
  });

  it("flags a non-default token fed to the agent as GHA_AGENT_CROSS_REPO_TOKEN (high)", () => {
    writeWf(tmp, "triage.yml", GITLOST_WF);
    const f = scanGitHubActionsWorkflows(tmp).find((x) => x.rule === "GHA_AGENT_CROSS_REPO_TOKEN");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("high");
  });

  it("does NOT flag a plain build workflow with no agent step", () => {
    writeWf(tmp, "ci.yml", `
name: CI
on: [push, pull_request]
permissions:
  issues: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
`);
    const rules = scanGitHubActionsWorkflows(tmp).map((x) => x.rule);
    expect(rules).not.toContain("GHA_AGENT_UNTRUSTED_PROMPT");
    expect(rules).not.toContain("GHA_AGENT_PUBLIC_POST");
    expect(rules).not.toContain("GHA_AGENT_CROSS_REPO_TOKEN");
  });

  it("does NOT flag an agent step whose prompt has no untrusted context (cron summary)", () => {
    writeWf(tmp, "daily.yml", `
name: daily
on:
  schedule:
    - cron: "0 9 * * *"
permissions:
  contents: read
jobs:
  summary:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Summarize yesterday's merged PRs."
`);
    const rules = scanGitHubActionsWorkflows(tmp).map((x) => x.rule);
    expect(rules).not.toContain("GHA_AGENT_UNTRUSTED_PROMPT");
  });

  it("flags an ungated issue-triggered agent as GHA_AGENT_NO_AUTHOR_GATE (medium)", () => {
    writeWf(tmp, "triage.yml", `
name: t
on: { issues: { types: [opened] } }
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Handle: \${{ github.event.issue.body }}"
`);
    const f = scanGitHubActionsWorkflows(tmp).find((x) => x.rule === "GHA_AGENT_NO_AUTHOR_GATE");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("medium");
  });

  it("does NOT flag GHA_AGENT_NO_AUTHOR_GATE when an author_association gate is present", () => {
    writeWf(tmp, "triage.yml", `
name: t
on: { issues: { types: [opened] } }
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    if: contains(fromJSON('["OWNER","MEMBER"]'), github.event.issue.author_association)
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Handle: \${{ github.event.issue.body }}"
`);
    const rules = scanGitHubActionsWorkflows(tmp).map((x) => x.rule);
    expect(rules).not.toContain("GHA_AGENT_NO_AUTHOR_GATE");
  });

  it("flags an agent invoked via a run: CLI (claude -p) reading issue context", () => {
    writeWf(tmp, "cli.yml", `
name: cli-agent
on: { issue_comment: { types: [created] } }
permissions:
  issues: write
jobs:
  a:
    runs-on: ubuntu-latest
    if: github.actor == 'trusted'
    steps:
      - run: claude -p "Respond to: \${{ github.event.comment.body }}"
`);
    const rules = scanGitHubActionsWorkflows(tmp).map((x) => x.rule);
    expect(rules).toContain("GHA_AGENT_UNTRUSTED_PROMPT");
    expect(rules).toContain("GHA_AGENT_PUBLIC_POST");
  });
});
