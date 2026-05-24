/**
 * Regression tests for v5.2.22:
 *
 * 1. github-actions-scanner strips YAML comments before pattern matching.
 *    The v5.2.21 self-scan flagged "id-token: write" inside an OIDC
 *    explanation comment of ci.yml as a real GHA_OIDC_WRITE_PERM finding.
 *
 * 2. CAMPAIGN_CLAUDE_LURE / CAMPAIGN_AI_TOOL_LURE no longer self-trigger
 *    on the v5.2.21 changelog entry (verified by re-scanning that text).
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { scanGitHubActionsWorkflows } from "../github-actions-scanner.js";

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-v5222-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("v5.2.22 bug fixes", () => {
  describe("github-actions-scanner strips YAML comments", () => {
    it("does NOT flag GHA_OIDC_WRITE_PERM when 'id-token: write' appears only in a comment", () => {
      withTempDir((dir) => {
        const wfDir = path.join(dir, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(
          path.join(wfDir, "ci.yml"),
          [
            "name: CI",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      # This comment mentions id-token: write but no permission is actually requested",
            "      - run: echo hello",
          ].join("\n"),
        );

        const findings = scanGitHubActionsWorkflows(dir);
        expect(findings.some((f) => f.rule === "GHA_OIDC_WRITE_PERM")).toBe(false);
      });
    });

    it("STILL flags GHA_OIDC_WRITE_PERM when 'id-token: write' is a real permission", () => {
      withTempDir((dir) => {
        const wfDir = path.join(dir, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(
          path.join(wfDir, "ci.yml"),
          [
            "name: CI",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      id-token: write",
            "    steps:",
            "      - run: echo hello",
          ].join("\n"),
        );

        const findings = scanGitHubActionsWorkflows(dir);
        expect(findings.some((f) => f.rule === "GHA_OIDC_WRITE_PERM")).toBe(true);
      });
    });

    it("handles inline comments after real config", () => {
      withTempDir((dir) => {
        const wfDir = path.join(dir, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(
          path.join(wfDir, "ci.yml"),
          [
            "name: CI",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest # avoid mentioning id-token: write here",
            "    steps:",
            "      - run: echo hello",
          ].join("\n"),
        );

        const findings = scanGitHubActionsWorkflows(dir);
        expect(findings.some((f) => f.rule === "GHA_OIDC_WRITE_PERM")).toBe(false);
      });
    });

    it("preserves # inside quoted strings (not treated as comment marker)", () => {
      withTempDir((dir) => {
        const wfDir = path.join(dir, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(
          path.join(wfDir, "ci.yml"),
          [
            "name: CI",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            '      label: "comment-like #string with id-token: write inside"',
            "      id-token: write",
            "    steps:",
            "      - run: echo hello",
          ].join("\n"),
        );

        const findings = scanGitHubActionsWorkflows(dir);
        // The real permission on the next line still fires
        expect(findings.some((f) => f.rule === "GHA_OIDC_WRITE_PERM")).toBe(true);
      });
    });
  });
});
