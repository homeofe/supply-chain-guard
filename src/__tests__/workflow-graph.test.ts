import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanWorkflowGraph } from "../workflow-graph.js";
import { applyInlineSuppressions } from "../policy-engine.js";

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

  describe("severity is scoped to the job that downloads, not the whole file", () => {
    it("does NOT let an unrelated job's chmod +x escalate a separate download-only job to critical", () => {
      writeWorkflows(tempDir, {
        "ci.yml": PRODUCER_PR_UPLOAD,
        "mixed.yml": [
          "name: Mixed",
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
          "  unrelated:",
          "    steps:",
          "      - run: chmod +x some-other-tool.sh",
        ].join("\n"),
      });

      const findings = scanWorkflowGraph(tempDir);
      const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("medium");
    });

    it("still flags critical when the SAME job both downloads and executes, even alongside a benign job", () => {
      writeWorkflows(tempDir, {
        "ci.yml": PRODUCER_PR_UPLOAD,
        "mixed.yml": [
          "name: Mixed",
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
          "  unrelated:",
          "    steps:",
          "      - run: echo hello",
        ].join("\n"),
      });

      const findings = scanWorkflowGraph(tempDir);
      const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("critical");
    });
  });

  describe("finding carries a line so scg-ignore-next-line can suppress it", () => {
    it("anchors the finding on the download step's line", () => {
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
          "      - uses: actions/download-artifact@v4", // line 9
          "        with:",
          "          name: build",
          "      - run: bash build/deploy.sh",
        ].join("\n"),
      });

      const findings = scanWorkflowGraph(tempDir);
      const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
      expect(f?.line).toBe(9);
    });

    it("is actually suppressible via scg-ignore-next-line above the download step", () => {
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
          "      # scg-ignore-next-line GHA_CROSS_WORKFLOW_ARTIFACT_TRUST reviewed, artifact is signed",
          "      - uses: actions/download-artifact@v4",
          "        with:",
          "          name: build",
          "      - run: bash build/deploy.sh",
        ].join("\n"),
      });

      const raw = scanWorkflowGraph(tempDir);
      expect(raw.some((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST")).toBe(true);

      const { findings, suppressedCount } = applyInlineSuppressions(raw, tempDir);
      expect(findings.some((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST")).toBe(false);
      expect(suppressedCount).toBeGreaterThanOrEqual(1);
    });
  });

  describe("an artifact relayed into a dependent job is still followed", () => {
    // The job-scoping fix must not turn the old file-wide FALSE POSITIVE into a
    // false negative. Here the download job never executes anything: it
    // re-uploads the PR artifact under a new name, and a dependent job runs it.
    // Scoping alone would report medium and drop the executing job entirely,
    // because its download name does not match the producer's upload.
    it("flags critical when a dependent job downloads the relay and executes it", () => {
      writeWorkflows(tempDir, {
        "ci.yml": PRODUCER_PR_UPLOAD,
        "relay.yml": [
          "name: Relay",
          "on:",
          "  workflow_run:",
          '    workflows: ["CI"]',
          "    types: [completed]",
          "jobs:",
          "  fetch:",
          "    steps:",
          "      - uses: actions/download-artifact@v4",
          "        with:",
          "          name: build",
          "      - uses: actions/upload-artifact@v4",
          "        with:",
          "          name: relayed",
          "  run-it:",
          "    needs: [fetch]",
          "    steps:",
          "      - uses: actions/download-artifact@v4",
          "        with:",
          "          name: relayed",
          "      - run: bash relayed/deploy.sh",
        ].join("\n"),
      });

      const findings = scanWorkflowGraph(tempDir);
      const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("critical");
    });

    // The other direction: without the `needs` edge the second job cannot
    // reliably receive the upload, so the chain is not followed and the
    // unrelated execution must NOT escalate the download-only job.
    it("does NOT escalate when the executing job does not depend on the downloading job", () => {
      writeWorkflows(tempDir, {
        "ci.yml": PRODUCER_PR_UPLOAD,
        "norelay.yml": [
          "name: NoRelay",
          "on:",
          "  workflow_run:",
          '    workflows: ["CI"]',
          "    types: [completed]",
          "jobs:",
          "  fetch:",
          "    steps:",
          "      - uses: actions/download-artifact@v4",
          "        with:",
          "          name: build",
          "      - uses: actions/upload-artifact@v4",
          "        with:",
          "          name: relayed",
          "  unrelated:",
          "    steps:",
          "      - uses: actions/download-artifact@v4",
          "        with:",
          "          name: something-else",
          "      - run: bash something-else/tool.sh",
        ].join("\n"),
      });

      const findings = scanWorkflowGraph(tempDir);
      const f = findings.find((f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("medium");
    });
  });

  describe("each finding is anchored on the download step that actually matched", () => {
    // Anchoring on the job's FIRST download puts scg-ignore-next-line on the
    // wrong line: a directive above the unrelated download would suppress the
    // risky one, and a directive above the risky one would do nothing.
    it("anchors on the matching download, not the job's first download", () => {
      writeWorkflows(tempDir, {
        "ci.yml": PRODUCER_PR_UPLOAD,
        "two.yml": [
          "name: Two",                                      // 1
          "on:",                                            // 2
          "  workflow_run:",                                // 3
          '    workflows: ["CI"]',                          // 4
          "    types: [completed]",                         // 5
          "jobs:",                                          // 6
          "  deploy:",                                      // 7
          "    steps:",                                     // 8
          "      - uses: actions/download-artifact@v4",     // 9  (unrelated)
          "        with:",                                  // 10
          "          name: unrelated-cache",                // 11
          "      - uses: actions/download-artifact@v4",     // 12 (the match)
          "        with:",                                  // 13
          "          name: build",                          // 14
        ].join("\n"),
      });

      const findings = scanWorkflowGraph(tempDir).filter(
        (f) => f.rule === "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].line, "must anchor on the download whose name matched").toBe(12);
    });
  });
});
