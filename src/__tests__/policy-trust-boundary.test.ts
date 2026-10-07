import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

const cloneHarness = vi.hoisted(() => ({
  sourceDir: null as string | null,
}));

// Exercise the production GitHub-target path without network access. Only the
// clone operation is substituted; every other child-process call stays real.
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  const fsModule = await import("node:fs");
  const realExecFileSync = actual.execFileSync as (
    file: string,
    args?: readonly string[],
    options?: unknown,
  ) => unknown;

  return {
    ...actual,
    execFileSync: (file: string, args?: readonly string[], options?: unknown): unknown => {
      const tool = file.split(/[\\/]/).pop()?.replace(/\.exe$/i, "");
      if (tool === "git" && args?.[0] === "clone" && cloneHarness.sourceDir) {
        const destination = args.at(-1);
        if (!destination) throw new Error("Missing clone destination");
        fsModule.cpSync(cloneHarness.sourceDir, destination, { recursive: true });
        return Buffer.alloc(0);
      }
      return realExecFileSync(file, args, options);
    },
  };
});

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { formatReport } from "../reporter.js";
import { handleMcpMessage } from "../mcp-server.js";
import { scanExtractedNpmFiles } from "../npm-scanner.js";
import type { Finding } from "../types.js";

/** Trips a critical EVAL_ATOB finding. */
// Built from parts so this test file does not trip the repository self-scan
// (critical rules now fire in test paths too).
const PAYLOAD = ["function boot(p) { return ev", "al(at", "ob(p)); }\nmodule.exports = { boot };\n"].join("");
const POLICY = ".supply-chain-guard.yml";

describe("policy file inside the scanned tree (issues 168 and 169)", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-policy-trust-"));
    fs.writeFileSync(path.join(dir, "app.js"), PAYLOAD);
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const writePolicy = (yaml: string): void =>
    fs.writeFileSync(path.join(dir, POLICY), yaml);

  describe("F2: severe suppression stays visible", () => {
    it.each([
      ["rules.disable", "rules:\n  disable:\n    EVAL_ATOB: reviewed\n"],
      ["ignore", 'ignore:\n  "app.js": reviewed\n'],
      ["suppress", "suppress:\n  - rule: EVAL_ATOB\n    reason: reviewed\n"],
      ["severityOverrides", "rules:\n  severityOverrides:\n    EVAL_ATOB: low\n"],
    ])("a local scan narrowed by %s reports the suppressed severe finding", async (_name, yaml) => {
      const control = await scan({ target: dir, format: "json", noHistory: true });
      writePolicy(yaml);
      const report = await scan({ target: dir, format: "json", noHistory: true });

      const evalAtob = report.findings.find((f) => f.rule === "EVAL_ATOB");
      // severityOverrides keeps the finding but downgrades it; the others remove it.
      if (_name === "severityOverrides") expect(evalAtob?.severity).toBe("low");
      else expect(evalAtob).toBeUndefined();
      const note = report.findings.find((f) => f.rule === "POLICY_SUPPRESSED_SEVERE");
      expect(note).toBeDefined();
      expect(note?.severity).toBe("medium");
      expect(note?.description).toContain("EVAL_ATOB");
      expect(control.summary.critical).toBe(1);
      expect(report.riskLevelBeforePolicy).toBe(control.riskLevel);
      expect(report.riskLevelBeforePolicy).not.toBe("clean");
      expect(report.maxSeverityBeforePolicy).toBe("critical");
      // JSON and text output both carry it.
      expect(JSON.parse(formatReport(report, "json")).riskLevelBeforePolicy).toBe(control.riskLevel);
      expect(formatReport(report, "text")).toContain("RISK BEFORE POLICY");
    }, 30_000);

    it("does not add the finding or the field when nothing severe was removed", async () => {
      writePolicy("rules:\n  disable:\n    NO_SUCH_RULE: reviewed\n");
      const report = await scan({ target: dir, format: "json", noHistory: true });
      expect(report.findings.map((f) => f.rule)).toContain("EVAL_ATOB");
      expect(report.findings.map((f) => f.rule)).not.toContain("POLICY_SUPPRESSED_SEVERE");
      expect(report.maxSeverityBeforePolicy).toBe("critical");
    }, 30_000);

    it("leaves a scan without a policy untouched", async () => {
      const report = await scan({ target: dir, format: "json", noHistory: true });
      expect(report.riskLevelBeforePolicy).toBeUndefined();
      expect(report.findings.map((f) => f.rule)).not.toContain("POLICY_SUPPRESSED_SEVERE");
    });

    it("a github-type scan ignores the policy shipped in the cloned tree", async () => {
      writePolicy("rules:\n  disable:\n    EVAL_ATOB: reviewed\n");
      cloneHarness.sourceDir = dir;
      let report;
      try {
        report = await scan({
          target: "https://github.com/someone/some-repo",
          format: "json",
          noHistory: true,
        });
      } finally {
        cloneHarness.sourceDir = null;
      }
      expect(report.scanType).toBe("github");
      expect(report.findings.map((f) => f.rule)).toContain("EVAL_ATOB");
      expect(report.policyEffect).toBeUndefined();
      expect(report.summary.critical).toBe(1);
    }, 30_000);

    it("a local scan with trustTargetPolicy false ignores the tree policy", async () => {
      writePolicy("rules:\n  disable:\n    EVAL_ATOB: reviewed\n");
      const report = await scan({
        target: dir,
        format: "json",
        noHistory: true,
        trustTargetPolicy: false,
      });
      expect(report.findings.map((f) => f.rule)).toContain("EVAL_ATOB");
      expect(report.policyEffect).toBeUndefined();
    }, 30_000);

    it("MCP scan_directory ignores the tree policy", async () => {
      writePolicy('ignore:\n  "**": reviewed\nrules:\n  disable:\n    EVAL_ATOB: reviewed\n');
      const response = (await handleMcpMessage({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "scan_directory", arguments: { path: dir } },
      })) as { result: { content: Array<{ text: string }> } };
      const summary = JSON.parse(response.result.content[0]!.text) as {
        topFindings: Array<{ rule: string }>;
      };
      expect(summary.topFindings.map((f) => f.rule)).toContain("EVAL_ATOB");
    }, 30_000);
  });

  describe("inline scg-ignore-next-line comments are scanned-content input", () => {
    const IGNORED = `// scg-ignore-next-line EVAL_ATOB reviewed\n${PAYLOAD}`;

    it("a local scan honours the comment but surfaces the hidden critical finding", async () => {
      fs.writeFileSync(path.join(dir, "app.js"), IGNORED);
      const control = await scan({ target: dir, format: "json", noHistory: true, trustTargetPolicy: false });
      const report = await scan({ target: dir, format: "json", noHistory: true });

      expect(report.findings.map((f) => f.rule)).not.toContain("EVAL_ATOB");
      expect(report.suppressedCount).toBeGreaterThan(0);
      const note = report.findings.find((f) => f.rule === "POLICY_SUPPRESSED_SEVERE");
      expect(note?.description).toContain("EVAL_ATOB");
      expect(report.riskLevelBeforePolicy).toBe(control.riskLevel);
      expect(report.maxSeverityBeforePolicy).toBe("critical");
    }, 30_000);

    it("a local scan with neither policy nor comment stays single-pass", async () => {
      const report = await scan({ target: dir, format: "json", noHistory: true });
      expect(report.riskLevelBeforePolicy).toBeUndefined();
    });

    it("a github-type scan does not let the comment hide a critical finding", async () => {
      fs.writeFileSync(path.join(dir, "app.js"), IGNORED);
      cloneHarness.sourceDir = dir;
      let report;
      try {
        report = await scan({
          target: "https://github.com/someone/some-repo",
          format: "json",
          noHistory: true,
        });
      } finally {
        cloneHarness.sourceDir = null;
      }
      expect(report.findings.map((f) => f.rule)).toContain("EVAL_ATOB");
      expect(report.summary.critical).toBe(1);
    }, 30_000);

    it("MCP scan_directory does not let the comment hide a critical finding", async () => {
      fs.writeFileSync(path.join(dir, "app.js"), IGNORED);
      const response = (await handleMcpMessage({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "scan_directory", arguments: { path: dir } },
      })) as { result: { content: Array<{ text: string }> } };
      const summary = JSON.parse(response.result.content[0]!.text) as {
        topFindings: Array<{ rule: string }>;
      };
      expect(summary.topFindings.map((f) => f.rule)).toContain("EVAL_ATOB");
    }, 30_000);

    it("an npm tarball tree is never suppressed by the comment", () => {
      fs.writeFileSync(path.join(dir, "payload.js"), IGNORED);
      fs.rmSync(path.join(dir, "app.js"));
      const findings: Finding[] = [];
      scanExtractedNpmFiles(dir, findings);
      const hit = findings.find((f) => f.rule === "EVAL_ATOB");
      expect(hit?.severity).toBe("critical");
    });
  });

  describe("F3: scanned-tree deny-list regexes are a safe subset", () => {
    const ADVERSARIAL = `// ${"a".repeat(40)}!\n`;

    it.each(["(a|a)+$", "(a|ab)+$", "(\\d|\\d\\d)+$", "(a+){2,30}$", "(a)\\1", "a(?=b)"])(
      "refuses %s from a tree policy and still finishes quickly",
      async (pattern) => {
        fs.writeFileSync(path.join(dir, "a.js"), ADVERSARIAL);
        writePolicy(`internalDisclosure:\n  patterns:\n    - "/${pattern}/"\n`);

        const started = Date.now();
        const report = await scan({ target: dir, format: "json", noHistory: true });
        expect(Date.now() - started).toBeLessThan(10_000);

        const refused = report.findings.filter((f) => f.rule === "INTERNAL_DENYLIST_REFUSED");
        expect(refused.length).toBeGreaterThan(0);
        expect(report.partialScan).toBe(true);
      },
      30_000,
    );

    it("still applies a plain literal deny pattern and a quantified single class", async () => {
      fs.writeFileSync(path.join(dir, "notes.js"), "// project-codename-orchid lives here\nconst id = 'ab123';\n");
      writePolicy(
        'internalDisclosure:\n  patterns:\n    - "project-codename-orchid"\n    - "/ab[0-9]{3}/"\n',
      );
      const report = await scan({ target: dir, format: "json", noHistory: true });
      expect(report.findings.filter((f) => f.rule === "INTERNAL_DENYLIST_MATCH").length).toBeGreaterThanOrEqual(1);
      expect(report.findings.map((f) => f.rule)).not.toContain("INTERNAL_DENYLIST_REFUSED");
    }, 30_000);
  });
});
