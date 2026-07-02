import { describe, it, expect, vi } from "vitest";
import {
  analyzeInstallCommand,
  escapeCmdShellArg,
  extractInstallSpecs,
  parseSpecToken,
  resolveManagerBinary,
  runInstallGuard,
  SUPPORTED_MANAGERS,
  type SpawnLike,
} from "../install-guard.js";
import { getBundledFeed, type FeedIOC } from "../threat-intel.js";

// Real bundled IOCs (threat-intel.ts BUNDLED_FEED, npm ecosystem):
// pinned entry - matches only this exact version
const PINNED_BAD = "axios@1.14.1";
// bare-name entry - matches every version (Phantom Bot npm DDoS campaign)
const BARE_BAD = "chalk-tempalte";
// scoped bare-name entry
const SCOPED_BAD = "@deadcode09284814/axios-util";

/** Spawn spy that never executes anything. */
function spawnSpy(status: number | null = 0): { fn: SpawnLike; calls: Array<{ command: string; args: string[]; options: { stdio: "inherit"; shell: false } }> } {
  const calls: Array<{ command: string; args: string[]; options: { stdio: "inherit"; shell: false } }> = [];
  const fn: SpawnLike = (command, args, options) => {
    calls.push({ command, args, options });
    return { status };
  };
  return { fn, calls };
}

describe("Install Guard", () => {
  describe("parseSpecToken", () => {
    it("should parse bare, pinned, and scoped specs", () => {
      expect(parseSpecToken("lodash")).toEqual({ raw: "lodash", name: "lodash" });
      expect(parseSpecToken("left-pad@1.3.0")).toEqual({ raw: "left-pad@1.3.0", name: "left-pad", version: "1.3.0" });
      expect(parseSpecToken("@types/node")).toEqual({ raw: "@types/node", name: "@types/node" });
      expect(parseSpecToken("@types/node@20.11.5")).toEqual({ raw: "@types/node@20.11.5", name: "@types/node", version: "20.11.5" });
    });

    it("should skip flags and non-registry specs", () => {
      expect(parseSpecToken("--save-dev")).toBeNull();
      expect(parseSpecToken("-g")).toBeNull();
      expect(parseSpecToken("./local-pkg")).toBeNull();
      expect(parseSpecToken("file:../local-pkg")).toBeNull();
      expect(parseSpecToken("pkg.tgz")).not.toBeNull(); // valid registry name shape
      expect(parseSpecToken("alias@npm:real-pkg@1.0.0")).toBeNull(); // protocol version
      expect(parseSpecToken("")).toBeNull();
    });
  });

  describe("extractInstallSpecs (verb + spec extraction)", () => {
    it("npm: install/i/add verbs with flags interleaved", () => {
      const result = extractInstallSpecs("npm", ["install", "-g", "lodash", "--save-dev", "@types/node@20.11.5"]);
      expect(result.installVerb).toBe(true);
      expect(result.specs.map((s) => s.name)).toEqual(["lodash", "@types/node"]);
      expect(extractInstallSpecs("npm", ["i", "left-pad@1.3.0"]).specs).toHaveLength(1);
      expect(extractInstallSpecs("npm", ["add", "left-pad"]).installVerb).toBe(true);
    });

    it("pnpm: add and install are install verbs", () => {
      const result = extractInstallSpecs("pnpm", ["add", "@scope/pkg@2.0.0"]);
      expect(result.installVerb).toBe(true);
      expect(result.specs).toEqual([{ raw: "@scope/pkg@2.0.0", name: "@scope/pkg", version: "2.0.0" }]);
      expect(extractInstallSpecs("pnpm", ["install"]).installVerb).toBe(true);
    });

    it("yarn: only add is an install verb (yarn install takes no specs)", () => {
      const added = extractInstallSpecs("yarn", ["add", "react", "react-dom@18.2.0", "--dev"]);
      expect(added.installVerb).toBe(true);
      expect(added.specs.map((s) => s.name)).toEqual(["react", "react-dom"]);
      expect(extractInstallSpecs("yarn", ["install"]).installVerb).toBe(false);
    });

    it("bun: add and install are install verbs", () => {
      const result = extractInstallSpecs("bun", ["add", "-d", "typescript@5.6.3"]);
      expect(result.installVerb).toBe(true);
      expect(result.specs).toEqual([{ raw: "typescript@5.6.3", name: "typescript", version: "5.6.3" }]);
      expect(extractInstallSpecs("bun", ["install"]).installVerb).toBe(true);
    });

    it("non-install verbs yield no specs", () => {
      expect(extractInstallSpecs("npm", ["run", "build"]).installVerb).toBe(false);
      expect(extractInstallSpecs("npm", ["test"]).installVerb).toBe(false);
      expect(extractInstallSpecs("pnpm", ["exec", "vitest"]).installVerb).toBe(false);
    });
  });

  describe("analyzeInstallCommand", () => {
    it("should block a pinned known-bad version (feed IOC + bad-version blocklist)", () => {
      const analysis = analyzeInstallCommand("npm", ["install", PINNED_BAD]);
      expect(analysis.blocked).toBe(true);
      const rules = analysis.verdicts[0].findings.map((f) => f.rule);
      expect(rules).toContain("THREAT_INTEL_PACKAGE_IOC");
      expect(rules).toContain("IOC_KNOWN_BAD_VERSION");
    });

    it("should block a bare-name feed IOC regardless of version", () => {
      expect(analyzeInstallCommand("npm", ["install", BARE_BAD]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", `${BARE_BAD}@9.9.9`]).blocked).toBe(true);
    });

    it("should block a scoped bare-name feed IOC", () => {
      const analysis = analyzeInstallCommand("pnpm", ["add", SCOPED_BAD]);
      expect(analysis.blocked).toBe(true);
      expect(analysis.verdicts[0].spec.name).toBe(SCOPED_BAD);
    });

    it("should not block the same package at a clean version", () => {
      // axios without a pin (or at a clean version) must pass - only 1.14.1/0.30.4 are compromised
      expect(analyzeInstallCommand("npm", ["install", "axios"]).blocked).toBe(false);
      expect(analyzeInstallCommand("npm", ["install", "axios@1.7.0"]).blocked).toBe(false);
    });

    it("should flag likely typosquats via the dependency risk analyzer", () => {
      const analysis = analyzeInstallCommand("npm", ["install", "expresss"]);
      expect(analysis.blocked).toBe(true);
      expect(analysis.verdicts[0].findings.some((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")).toBe(true);
    });

    it("should pass a clean install command", () => {
      const analysis = analyzeInstallCommand("npm", ["install", "commander@12.0.0", "--save-exact"]);
      expect(analysis.blocked).toBe(false);
      expect(analysis.verdicts.every((v) => v.findings.length === 0)).toBe(true);
    });

    it("should pass non-install verbs without analysis", () => {
      const analysis = analyzeInstallCommand("npm", ["run", "build"]);
      expect(analysis.installVerb).toBe(false);
      expect(analysis.specs).toHaveLength(0);
      expect(analysis.blocked).toBe(false);
    });

    it("should reject unknown managers (no arbitrary command execution)", () => {
      expect(() => analyzeInstallCommand("pip", ["install", "requests"])).toThrow(/Unsupported package manager/);
      expect(() => analyzeInstallCommand("npm.cmd", ["install", "lodash"])).toThrow(/Unsupported/);
      expect(() => analyzeInstallCommand("npm; rm -rf /", ["install"])).toThrow(/Unsupported/);
      expect(SUPPORTED_MANAGERS).toEqual(["npm", "pnpm", "yarn", "bun"]);
    });

    it("should match entries from an injected (refreshed) feed", () => {
      const feed: FeedIOC[] = [
        ...getBundledFeed(),
        { type: "package", value: "evil-extra-guard-test@1.0.0", severity: "critical", confidence: 1.0 },
      ];
      expect(analyzeInstallCommand("npm", ["install", "evil-extra-guard-test@1.0.0"], feed).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "evil-extra-guard-test@1.0.0"], getBundledFeed()).blocked).toBe(false);
    });
  });

  describe("resolveManagerBinary", () => {
    it("should resolve .cmd shims on Windows and plain names elsewhere", () => {
      expect(resolveManagerBinary("npm", "win32")).toBe("npm.cmd");
      expect(resolveManagerBinary("yarn", "win32")).toBe("yarn.cmd");
      expect(resolveManagerBinary("npm", "linux")).toBe("npm");
      expect(resolveManagerBinary("bun", "darwin")).toBe("bun");
    });
  });

  describe("runInstallGuard", () => {
    it("should exit 2 on findings WITHOUT invoking the manager", () => {
      const spy = spawnSpy();
      const log = vi.fn();
      const code = runInstallGuard("npm", ["install", PINNED_BAD], { spawn: spy.fn, log });
      expect(code).toBe(2);
      expect(spy.calls).toHaveLength(0);
      expect(log.mock.calls.flat().join("\n")).toContain("BLOCKED");
    });

    it("--force should invoke the manager despite findings, with a warning", () => {
      const spy = spawnSpy(0);
      const log = vi.fn();
      const args = ["install", PINNED_BAD];
      const code = runInstallGuard("npm", args, { spawn: spy.fn, log, force: true });
      expect(code).toBe(0);
      expect(spy.calls).toHaveLength(1);
      expect(spy.calls[0].args).toEqual(args);
      expect(log.mock.calls.flat().join("\n")).toContain("WARNING");
    });

    it("--dry-run should never spawn, with or without findings", () => {
      const spy = spawnSpy();
      const log = vi.fn();
      expect(runInstallGuard("npm", ["install", BARE_BAD], { spawn: spy.fn, log, dryRun: true })).toBe(2);
      expect(runInstallGuard("npm", ["install", "commander"], { spawn: spy.fn, log, dryRun: true })).toBe(0);
      // Even --force does not override --dry-run into an execution
      expect(runInstallGuard("npm", ["install", BARE_BAD], { spawn: spy.fn, log, dryRun: true, force: true })).toBe(2);
      expect(spy.calls).toHaveLength(0);
    });

    it("clean install should pass through with args untouched and propagate the exit code", () => {
      const spy = spawnSpy(3);
      const args = ["install", "--save-dev", "commander@12.0.0"];
      const code = runInstallGuard("npm", args, { spawn: spy.fn, log: vi.fn() });
      expect(code).toBe(3);
      expect(spy.calls).toHaveLength(1);
      expect(spy.calls[0].args).toEqual(["install", "--save-dev", "commander@12.0.0"]);
      expect(spy.calls[0].options).toEqual({ stdio: "inherit", shell: false });
      const expectedBinary = process.platform === "win32" ? "npm.cmd" : "npm";
      expect(spy.calls[0].command).toBe(expectedBinary);
    });

    it("non-install verbs should pass straight through", () => {
      const spy = spawnSpy(0);
      const code = runInstallGuard("pnpm", ["run", "build", "--filter", "web"], { spawn: spy.fn, log: vi.fn() });
      expect(code).toBe(0);
      expect(spy.calls).toHaveLength(1);
      expect(spy.calls[0].args).toEqual(["run", "build", "--filter", "web"]);
    });

    it("should reject unknown managers before any spawn", () => {
      const spy = spawnSpy();
      expect(() => runInstallGuard("brew", ["install", "wget"], { spawn: spy.fn, log: vi.fn() })).toThrow(/Unsupported/);
      expect(spy.calls).toHaveLength(0);
    });

    it("should surface spawn errors as thrown errors", () => {
      const failing: SpawnLike = () => ({ status: null, error: new Error("ENOENT") });
      expect(() => runInstallGuard("npm", ["install", "commander"], { spawn: failing, log: vi.fn() })).toThrow(/Failed to run/);
    });
  });
});

// ---------------------------------------------------------------------------
// v5.6.0 verification-gate regressions (M1 injection, M2 aliases, M3 bypass)
// ---------------------------------------------------------------------------

describe("v5.6.0 gate: install-verb bypasses are closed", () => {
  const BAD = "event-stream@3.3.6"; // pinned npm IOC in the bundled feed

  it("M2: npm typo-aliases still scan (isntall, i, in, ins)", () => {
    for (const verb of ["isntall", "i", "in", "ins", "install", "add"]) {
      const a = analyzeInstallCommand("npm", [verb, BAD]);
      expect(a.installVerb, verb).toBe(true);
      expect(a.blocked, verb).toBe(true);
    }
  });

  it("M2: pnpm i and bun i scan", () => {
    expect(analyzeInstallCommand("pnpm", ["i", BAD]).blocked).toBe(true);
    expect(analyzeInstallCommand("bun", ["i", BAD]).blocked).toBe(true);
  });

  it("M3: `yarn global add <bad>` is scanned, not passed through", () => {
    const a = analyzeInstallCommand("yarn", ["global", "add", BAD]);
    expect(a.installVerb).toBe(true);
    expect(a.blocked).toBe(true);
  });

  it("M3: a value-taking global flag before the verb does not hide it", () => {
    const a = analyzeInstallCommand("npm", ["--prefix", "./x", "install", BAD]);
    expect(a.installVerb).toBe(true);
    expect(a.blocked).toBe(true);
  });

  it("M3-low: a flag value is not misread as a package spec", () => {
    const a = analyzeInstallCommand("npm", ["install", "--prefix", "x", "lodash"]);
    expect(a.specs.map((s) => s.name)).toEqual(["lodash"]);
  });

  it("genuine non-install verbs still pass through unscanned", () => {
    expect(analyzeInstallCommand("npm", ["run", "build"]).installVerb).toBe(false);
    expect(analyzeInstallCommand("npm", ["ci"]).installVerb).toBe(false);
    expect(analyzeInstallCommand("yarn", ["install"]).installVerb).toBe(false);
  });
});

describe("v5.6.0 gate M1: cmd.exe arg escaping is double-escaped", () => {
  it("double-escapes metacharacters (cross-spawn doubleEscapeMetaChars)", () => {
    // Single-escape of `foo&bar` would be `^"foo^&bar^"`; the .cmd shim
    // re-parses %*, so we need the two-pass form.
    expect(escapeCmdShellArg("foo&bar")).toBe('^^^"foo^^^&bar^^^"');
  });

  it("neutralizes the gate PoC payload (every & is caret-escaped)", () => {
    const out = escapeCmdShellArg('x"&echo INJECTED&"');
    // No bare & survives: each is preceded by a caret run.
    expect(/[^^]&/.test(out)).toBe(false);
    expect(out).toContain("^&");
  });
});
