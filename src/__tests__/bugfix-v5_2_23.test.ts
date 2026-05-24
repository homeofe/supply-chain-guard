/**
 * Regression test for v5.2.23: WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH
 * was firing on workflows that ran `npm install -g npm@latest` because
 * its `@latest`-detector regex was unscoped and matched any `@latest`
 * substring in the file, not just GitHub Action `uses:` references.
 *
 * That false-positive showed up on supply-chain-guard's own self-scan
 * after v5.2.20 introduced `npm install -g npm@latest` as the OIDC
 * trusted-publishing setup step.
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { modelWorkflows } from "../workflow-modeler.js";

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-v5223-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("v5.2.23: WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH scope fix", () => {
  it("does NOT fire on `npm install -g npm@latest` in publish workflow", () => {
    withTempDir((dir) => {
      const wfDir = path.join(dir, ".github", "workflows");
      fs.mkdirSync(wfDir, { recursive: true });
      fs.writeFileSync(
        path.join(wfDir, "ci.yml"),
        [
          "name: CI",
          "jobs:",
          "  publish:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4",
          "      - run: npm install -g npm@latest",
          "      - run: npm publish --provenance",
        ].join("\n"),
      );

      const findings = modelWorkflows(dir);
      expect(
        findings.some((f) => f.rule === "WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH"),
      ).toBe(false);
    });
  });

  it("STILL fires when a real GitHub Action is pinned to @main", () => {
    withTempDir((dir) => {
      const wfDir = path.join(dir, ".github", "workflows");
      fs.mkdirSync(wfDir, { recursive: true });
      fs.writeFileSync(
        path.join(wfDir, "release.yml"),
        [
          "name: Release",
          "jobs:",
          "  publish:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@main", // unpinned to a mutable branch
          "      - run: npm publish",
        ].join("\n"),
      );

      const findings = modelWorkflows(dir);
      expect(
        findings.some((f) => f.rule === "WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH"),
      ).toBe(true);
    });
  });

  it("STILL fires when a real GitHub Action is pinned to @master / @latest / @dev", () => {
    for (const tag of ["master", "latest", "dev"]) {
      withTempDir((dir) => {
        const wfDir = path.join(dir, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(
          path.join(wfDir, "release.yml"),
          [
            "name: Release",
            "jobs:",
            "  publish:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            `      - uses: some-org/some-action@${tag}`,
            "      - run: npm publish",
          ].join("\n"),
        );

        const findings = modelWorkflows(dir);
        expect(
          findings.some((f) => f.rule === "WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH"),
          `should fire for @${tag}`,
        ).toBe(true);
      });
    }
  });

  it("does NOT fire when all actions are pinned to commit SHAs", () => {
    withTempDir((dir) => {
      const wfDir = path.join(dir, ".github", "workflows");
      fs.mkdirSync(wfDir, { recursive: true });
      fs.writeFileSync(
        path.join(wfDir, "ci.yml"),
        [
          "name: CI",
          "jobs:",
          "  publish:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4",
          "      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4",
          "      - run: npm publish",
        ].join("\n"),
      );

      const findings = modelWorkflows(dir);
      expect(
        findings.some((f) => f.rule === "WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH"),
      ).toBe(false);
    });
  });
});
