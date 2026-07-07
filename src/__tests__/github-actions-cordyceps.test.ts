import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanGitHubActionsWorkflows } from "../github-actions-scanner.js";

/**
 * v5.7 Cordyceps coverage: trigger-aware single-file rules.
 *
 * Content is built with array.join("\n") so the `${{ ... }}` GitHub expression
 * syntax is never mis-parsed as a JS template literal.
 */
function writeWorkflow(baseDir: string, name: string, content: string) {
  const workflowDir = path.join(baseDir, ".github", "workflows");
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(path.join(workflowDir, name), content);
}

describe("GHA Cordyceps single-file rules (v5.7)", () => {
  let tempDir: string;
  beforeEach(() => { tempDir = fs.mkdtempSync(path.join("/tmp", "scg-gha-cord-")); });
  afterEach(() => { fs.rmSync(tempDir, { recursive: true, force: true }); });

  it("flags pull_request_target as a privileged trigger", () => {
    writeWorkflow(tempDir, "pt.yml", [
      "on: pull_request_target",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    const f = findings.find((f) => f.rule === "GHA_PRIVILEGED_TRIGGER");
    expect(f).toBeDefined();
    // Downgraded to low in v5.7: a privileged trigger is context, not itself a
    // vulnerability - it should not add standalone medium noise to CI gates.
    expect(f?.severity).toBe("low");
  });

  it("flags workflow_run as a privileged trigger", () => {
    writeWorkflow(tempDir, "wr.yml", [
      "on:",
      "  workflow_run:",
      '    workflows: ["CI"]',
      "    types: [completed]",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PRIVILEGED_TRIGGER")).toBe(true);
  });

  it("does NOT flag a plain push/pull_request workflow as privileged", () => {
    writeWorkflow(tempDir, "ci.yml", [
      "on: [push, pull_request]",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PRIVILEGED_TRIGGER")).toBe(false);
  });

  it("flags a pwn-request: pull_request_target + checkout of PR head", () => {
    writeWorkflow(tempDir, "pwn.yml", [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm ci && npm run build",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    const f = findings.find((f) => f.rule === "GHA_PWN_REQUEST_CHECKOUT");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("does NOT flag pwn-request for a plain pull_request checkout of head (sandboxed, read-only token)", () => {
    writeWorkflow(tempDir, "safe.yml", [
      "on: pull_request",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm ci",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PWN_REQUEST_CHECKOUT")).toBe(false);
  });

  it("flags github-script code injection with untrusted event context", () => {
    writeWorkflow(tempDir, "gs.yml", [
      "on: issue_comment",
      "jobs:",
      "  c:",
      "    steps:",
      "      - uses: actions/github-script@v7",
      "        with:",
      "          script: |",
      "            const x = 1",
      "            console.log('${{ github.event.comment.body }}')",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    const f = findings.find((f) => f.rule === "GHA_GITHUB_SCRIPT_INJECTION");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("high");
  });

  it("does NOT flag a github-script step without untrusted interpolation", () => {
    writeWorkflow(tempDir, "gs-safe.yml", [
      "on: push",
      "jobs:",
      "  c:",
      "    steps:",
      "      - uses: actions/github-script@v7",
      "        with:",
      "          script: |",
      "            core.setOutput('ok', 'yes')",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_GITHUB_SCRIPT_INJECTION")).toBe(false);
  });

  it("broadens script injection to comment.body in a run step (previously missed)", () => {
    writeWorkflow(tempDir, "inj.yml", [
      "on: issue_comment",
      "jobs:",
      "  c:",
      "    steps:",
      '      - run: echo "${{ github.event.comment.body }}"',
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(true);
  });

  it("flags permissions: write-all", () => {
    writeWorkflow(tempDir, "wa.yml", [
      "on: push",
      "permissions: write-all",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    const f = findings.find((f) => f.rule === "GHA_PERMS_WRITE_ALL");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("high");
  });

  it("flags missing permissions on a privileged trigger (broad default token)", () => {
    writeWorkflow(tempDir, "pt2.yml", [
      "on: pull_request_target",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    const f = findings.find((f) => f.rule === "GHA_PERMS_DEFAULT_BROAD");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("does NOT flag missing permissions when a top-level permissions block is present", () => {
    writeWorkflow(tempDir, "pt3.yml", [
      "on: pull_request_target",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PERMS_DEFAULT_BROAD")).toBe(false);
  });

  it("does NOT flag missing permissions on a non-privileged trigger", () => {
    writeWorkflow(tempDir, "push.yml", [
      "on: push",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PERMS_DEFAULT_BROAD")).toBe(false);
  });

  // ── v5.7 review fixes ─────────────────────────────────────────────────────

  it("flags pwn-request via a refs/pull/N/merge checkout ref", () => {
    writeWorkflow(tempDir, "pwn-num.yml", [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: refs/pull/${{ github.event.pull_request.number }}/merge",
      "      - run: npm ci",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    const f = findings.find((f) => f.rule === "GHA_PWN_REQUEST_CHECKOUT");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("flags pwn-request via a step-output checkout ref under workflow_run", () => {
    writeWorkflow(tempDir, "pwn-step.yml", [
      "on:",
      "  workflow_run:",
      '    workflows: ["CI"]',
      "    types: [completed]",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ steps.getpr.outputs.head_sha }}",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PWN_REQUEST_CHECKOUT")).toBe(true);
  });

  it("does NOT flag github.event.pull_request.base.ref as script injection (maintainer-controlled)", () => {
    writeWorkflow(tempDir, "baseref.yml", [
      "on: pull_request_target",
      "jobs:",
      "  deploy:",
      "    steps:",
      '      - run: echo "${{ github.event.pull_request.base.ref }}"',
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(false);
  });

  it("flags GHA_PERMS_DEFAULT_BROAD when a sibling job lacks its own permissions", () => {
    writeWorkflow(tempDir, "siblings.yml", [
      "on: pull_request_target",
      "jobs:",
      "  lint:",
      "    permissions:",
      "      contents: read",
      "    steps:",
      "      - run: echo lint",
      "  build:",
      "    steps:",
      "      - run: echo build",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PERMS_DEFAULT_BROAD")).toBe(true);
  });

  it("does NOT flag GHA_PERMS_DEFAULT_BROAD when every job declares its own permissions", () => {
    writeWorkflow(tempDir, "alljobs.yml", [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    permissions:",
      "      contents: read",
      "    steps:",
      "      - run: echo build",
    ].join("\n"));
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PERMS_DEFAULT_BROAD")).toBe(false);
  });
});
