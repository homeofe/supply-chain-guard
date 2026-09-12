/**
 * Tests for workflow AST performance pre-filter.
 *
 * Verifies that shouldParseWorkflow rejects non-workflow documents and oversized
 * dependencies before line-splitting or allocating AST objects, preventing V8
 * heap exhaustion while correctly accepting valid GitHub Actions workflow structures.
 */

import { afterEach, describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { shouldParseWorkflow, parseWorkflow } from "../workflow-ast.js";
import { scan } from "../scanner.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("workflow AST performance pre-filter", () => {
  describe("shouldParseWorkflow", () => {
    it("accepts valid GitHub Actions workflows with standard root keys", () => {
      const validWorkflow1 = `
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`;
      expect(shouldParseWorkflow(validWorkflow1)).toBe(true);

      const validWorkflow2 = `
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
`;
      expect(shouldParseWorkflow(validWorkflow2)).toBe(true);

      const validWorkflow3 = `
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
`;
      expect(shouldParseWorkflow(validWorkflow3)).toBe(true);

      const validWorkflow4 = `
env:
  NODE_ENV: test
jobs:
  lint:
    runs-on: ubuntu-latest
`;
      expect(shouldParseWorkflow(validWorkflow4)).toBe(true);
    });

    it("rejects empty or whitespace-only content", () => {
      expect(shouldParseWorkflow("")).toBe(false);
      expect(shouldParseWorkflow("   \n\n\t   ")).toBe(false);
    });

    it("rejects non-workflow YAML and other configuration formats", () => {
      const dockerCompose = `
version: "3.8"
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
`;
      expect(shouldParseWorkflow(dockerCompose)).toBe(false);

      const packageJson = JSON.stringify({
        name: "test-package",
        version: "1.0.0",
        scripts: { test: "vitest" },
      });
      expect(shouldParseWorkflow(packageJson)).toBe(false);

      const plainText = "This is a documentation file explaining workflow architecture.";
      expect(shouldParseWorkflow(plainText)).toBe(false);
    });

    it("rejects YAML files that only contain comments", () => {
      const commentsOnly = `
# This file is commented out
# name: Commented Out
# on: push
# jobs:
#   test:
`;
      expect(shouldParseWorkflow(commentsOnly)).toBe(false);
    });
  });

  describe("parseWorkflow with pre-filter short-circuit", () => {
    it("returns empty AST structure immediately for non-workflow content", () => {
      const nonWorkflow = `
database:
  host: localhost
  port: 5432
  user: postgres
`;
      const ast = parseWorkflow(nonWorkflow);
      expect(ast.triggers).toHaveLength(0);
      expect(ast.workflowRunWorkflows).toHaveLength(0);
      expect(ast.jobs).toHaveLength(0);
      expect(ast.permissions.declared).toBe(false);
    });

    it("efficiently handles oversized non-workflow data without heap bloat", () => {
      // Simulate large text file (e.g. bundle or lockfile content)
      const largeContent = "console.log('padding data line');\n".repeat(10000);
      const start = Date.now();
      const ast = parseWorkflow(largeContent);
      const elapsed = Date.now() - start;

      expect(ast.jobs).toHaveLength(0);
      // Fast regex rejection should take less than 100ms
      expect(elapsed).toBeLessThan(100);
    });

    it("fully parses workflow structure when root keys match", () => {
      const workflow = `
name: Security Audit
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Run audit
        run: npm audit
`;
      const ast = parseWorkflow(workflow);
      expect(ast.name).toBe("Security Audit");
      expect(ast.triggers).toContain("pull_request_target");
      expect(ast.permissions.declared).toBe(true);
      expect(ast.permissions.scopes.contents).toBe("read");
      expect(ast.permissions.scopes["id-token"]).toBe("write");
      expect(ast.jobs).toHaveLength(1);
      expect(ast.jobs[0].id).toBe("scan");
      expect(ast.jobs[0].steps).toHaveLength(2);
      expect(ast.jobs[0].steps[0].uses).toBe("actions/checkout@v4");
      expect(ast.jobs[0].steps[1].run).toBe("npm audit");
    });

    it("detects a dangerous workflow whose root keys are all quoted", async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-quoted-workflow-"));
      tempDirs.push(dir);
      const workflowDir = path.join(dir, ".github", "workflows");
      fs.mkdirSync(workflowDir, { recursive: true });
      fs.writeFileSync(path.join(workflowDir, "quoted.yml"), [
        '"name": Quoted workflow',
        '"on": pull_request_target',
        '"permissions":',
        "  contents: write",
        '"jobs":',
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: echo ${{ github.event.pull_request.head.sha }}",
      ].join("\n"));

      const report = await scan({ target: dir, noHistory: true });
      expect(report.findings.some((finding) => finding.rule === "GHA_PPE_PULL_TARGET")).toBe(true);
    });
  });
});
