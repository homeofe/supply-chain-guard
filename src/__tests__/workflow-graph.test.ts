import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanWorkflowGraph } from "../workflow-graph.js";

/**
 * v5.7 cross-workflow trust-boundary pass (the core Cordyceps detection).
 *
 * The danger is a composition that spans TWO files: a low-privilege
 * PR-triggered producer uploads an artifact, and a privileged workflow_run
 * consumer downloads (and often executes) it with the maintainer token.
 * No single file is wrong - which is exactly why single-file scanners miss it.
 */
function writeWorkflows(baseDir: string, workflows: Record<string, string>) {
  const dir = path.join(baseDir, ".github", "workflows");
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(workflows)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
}

const PRODUCER_PR_UPLOAD = [
  "name: CI",
  "on: pull_request",
  "jobs:",
  "  build:",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - run: npm ci && npm run build",
  "      - uses: actions/upload-artifact@v4",
  "        with:",
  "          name: build",
  "          path: dist/",
].join("\n");

describe("scanWorkflowGraph cross-workflow artifact trust (v5.7)", () => {
  let tempDir: string;
  beforeEach(() => { tempDir = fs.mkdtempSync(path.join("/tmp", "scg-wfgraph-")); });
  afterEach(() => { fs.rmSync(tempDir, { recursive: true, force: true }); });

  it("flags a workflow_run consumer that downloads AND executes a PR-produced artifact (critical)", () => {
    writeWorkflows(tempDir, {
      "ci.yml": PRODUCER_PR_UPLOAD,
      "deploy.yml": [
        "name: Deploy",
        "on:",
        "  workflow_run:",
        '    workflows: ["CI"]',
        "    types: [completed]",
        "jobs:",
        "  deploy:",
        "    steps:",
        "      - uses: actions/download-artifact@v4",
        "        with:",
        "          name: build",
        "      - run: bash build/deploy.sh",
      ].join("\n"),
    });

    const findings = scanWorkflowGraph(tempDir);
    const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
    expect(f?.file).toContain("deploy.yml");
    // names the producer that crosses the trust boundary
    expect(f?.description).toContain("CI");
  });

  it("flags a download-only workflow_run consumer at medium severity", () => {
    writeWorkflows(tempDir, {
      "ci.yml": PRODUCER_PR_UPLOAD,
      "report.yml": [
        "name: Report",
        "on:",
        "  workflow_run:",
        '    workflows: ["CI"]',
        "    types: [completed]",
        "jobs:",
        "  report:",
        "    steps:",
        "      - uses: actions/download-artifact@v4",
        "        with:",
        "          name: build",
        "      - run: echo done",
      ].join("\n"),
    });

    const findings = scanWorkflowGraph(tempDir);
    const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("flags a consumer that downloads via `gh run download` then executes it (critical)", () => {
    writeWorkflows(tempDir, {
      "ci.yml": PRODUCER_PR_UPLOAD,
      "deploy.yml": [
        "name: Deploy",
        "on:",
        "  workflow_run:",
        '    workflows: ["CI"]',
        "    types: [completed]",
        "jobs:",
        "  deploy:",
        "    steps:",
        "      - run: gh run download ${{ github.event.workflow_run.id }} -n build",
        "      - run: bash build/deploy.sh",
      ].join("\n"),
    });

    const findings = scanWorkflowGraph(tempDir);
    const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("does NOT escalate to critical when the consumer only runs a checked-in repo script", () => {
    writeWorkflows(tempDir, {
      "ci.yml": PRODUCER_PR_UPLOAD,
      "report.yml": [
        "name: Report",
        "on:",
        "  workflow_run:",
        '    workflows: ["CI"]',
        "    types: [completed]",
        "jobs:",
        "  report:",
        "    steps:",
        "      - uses: actions/download-artifact@v4",
        "        with:",
        "          name: build",
        "      - run: node scripts/post-comment.js",
      ].join("\n"),
    });

    const findings = scanWorkflowGraph(tempDir);
    const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("does NOT flag when the producer is triggered by a trusted event (push)", () => {
    writeWorkflows(tempDir, {
      "ci.yml": [
        "name: CI",
        "on: push",
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/upload-artifact@v4",
        "        with:",
        "          name: build",
      ].join("\n"),
      "deploy.yml": [
        "name: Deploy",
        "on:",
        "  workflow_run:",
        '    workflows: ["CI"]',
        "    types: [completed]",
        "jobs:",
        "  deploy:",
        "    steps:",
        "      - uses: actions/download-artifact@v4",
        "      - run: bash build/deploy.sh",
      ].join("\n"),
    });

    const findings = scanWorkflowGraph(tempDir);
    expect(findings.some((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST")).toBe(false);
  });

  it("does NOT flag a workflow_run consumer that downloads no artifact", () => {
    writeWorkflows(tempDir, {
      "ci.yml": PRODUCER_PR_UPLOAD,
      "notify.yml": [
        "name: Notify",
        "on:",
        "  workflow_run:",
        '    workflows: ["CI"]',
        "    types: [completed]",
        "jobs:",
        "  notify:",
        "    steps:",
        "      - run: echo notified",
      ].join("\n"),
    });

    const findings = scanWorkflowGraph(tempDir);
    expect(findings.some((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST")).toBe(false);
  });

  it("does NOT flag a lone PR producer with no privileged consumer", () => {
    writeWorkflows(tempDir, { "ci.yml": PRODUCER_PR_UPLOAD });
    const findings = scanWorkflowGraph(tempDir);
    expect(findings.some((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST")).toBe(false);
  });

  it("returns no findings when there is no workflows directory", () => {
    const findings = scanWorkflowGraph(tempDir);
    expect(findings).toHaveLength(0);
  });
});
