import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scanWorkflowGraph } from "../workflow-graph.js";

/**
 * GHA_CROSS_WORKFLOW_ARTIFACT_TRUST counts a step as a consumer only when it
 * retrieves artifact contents. Listing a run's artifacts (to count them or to
 * check that one exists) reads metadata the producer cannot use to run code.
 */
const RULE = "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST";

const PRODUCER = [
  "name: CI",
  "on: pull_request",
  "jobs:",
  "  build:",
  "    steps:",
  "      - run: npm ci && npm run build",
  "      - uses: actions/upload-artifact@v4",
  "        with:",
  "          name: build",
  "          path: dist/",
].join("\n");

function consumer(script: string[]): string {
  return [
    "name: Report",
    "on:",
    "  workflow_run:",
    '    workflows: ["CI"]',
    "    types: [completed]",
    "jobs:",
    "  report:",
    "    steps:",
    "      - uses: actions/github-script@v7",
    "        with:",
    "          script: |",
    ...script.map((l) => `            ${l}`),
  ].join("\n");
}

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-wfgraph-list-"));
  fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".github", "workflows", "ci.yml"), PRODUCER);
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function scanWith(script: string[]) {
  fs.writeFileSync(path.join(dir, ".github", "workflows", "report.yml"), consumer(script));
  return scanWorkflowGraph(dir).filter((f) => f.rule === RULE);
}

describe("GHA_CROSS_WORKFLOW_ARTIFACT_TRUST: listing is not downloading", () => {
  it("does not fire when the script only lists the run's artifacts", () => {
    expect(
      scanWith([
        "const { data } = await github.rest.actions.listWorkflowRunArtifacts({",
        "  owner: context.repo.owner, repo: context.repo.repo, run_id: context.payload.workflow_run.id,",
        "});",
        "core.setOutput('count', data.total_count);",
      ]),
    ).toHaveLength(0);
  });

  it("fires when the script lists and then downloads an artifact", () => {
    const found = scanWith([
      "const { data } = await github.rest.actions.listWorkflowRunArtifacts({ owner, repo, run_id });",
      "const zip = await github.rest.actions.downloadArtifact({",
      "  owner, repo, artifact_id: data.artifacts[0].id, archive_format: 'zip',",
      "});",
    ]);
    expect(found).toHaveLength(1);
    expect(found[0]!.line).toBe(9);
  });

  it("fires when the script fetches the artifact's archive URL", () => {
    const found = scanWith([
      "const { data } = await github.rest.actions.listWorkflowRunArtifacts({ owner, repo, run_id });",
      "await exec.exec('curl', ['-L', '-o', 'a.zip', data.artifacts[0].archive_download_url]);",
    ]);
    expect(found).toHaveLength(1);
  });

  it("does not recommend provenance attestation, which the rule does not read", () => {
    const found = scanWith(["await github.rest.actions.downloadArtifact({ owner, repo, artifact_id, archive_format: 'zip' });"]);
    expect(found).toHaveLength(1);
    expect(found[0]!.recommendation).not.toMatch(/attest|provenance/i);
  });
});
