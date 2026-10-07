import { describe, it, expect, vi } from "vitest";
import {
  analyzeInstallCommand,
  runInstallGuard,
  type SpawnLike,
} from "../install-guard.js";
import type { FeedIOC } from "../threat-intel.js";

// A feed holding one bare npm package IOC. Injecting it keeps the test off the
// bundled feed, which changes daily.
const EVIL = "evilpkg";
const FEED: FeedIOC[] = [
  {
    type: "package",
    value: EVIL,
    severity: "critical",
    confidence: 1,
    family: "test-family",
    campaign: "test-campaign",
  } as FeedIOC,
];

function spawnSpy(): { fn: SpawnLike; calls: string[][] } {
  const calls: string[][] = [];
  const fn: SpawnLike = (_command, args) => {
    calls.push(args);
    return { status: 0 };
  };
  return { fn, calls };
}

describe("F19: install guard does not read a real command line as package-free", () => {
  const MUST_BLOCK: Array<[string, string[]]> = [
    ["npm", ["install", "--save-exact", EVIL]],
    ["pnpm", ["add", "-w", EVIL]],
    ["npm", ["exec", "--cache", "x", EVIL]],
    ["npm", ["it", EVIL]],
    ["npm", ["install-test", EVIL]],
    ["npm", ["link", EVIL]],
    ["pnpm", ["dlx", EVIL]],
    ["yarn", ["dlx", EVIL]],
    ["bun", ["x", EVIL]],
    ["npm", ["x", EVIL]],
    // value flags that must keep working (controls from the finding)
    ["npm", ["i", "--filter", "a", EVIL]],
    ["yarn", ["add", "--cwd", "x", EVIL]],
    ["npm", ["--prefix", "./x", "install", EVIL]],
    ["npm", ["-w", "ws", "install", EVIL]],
    ["pnpm", ["--filter", "web", "add", EVIL]],
    ["pnpm", ["dlx", "--package", EVIL, "cmd"]],
    ["npm", ["exec", "--registry", "hxxps://registry.example[.]invalid", "--", EVIL]],
  ];

  for (const [manager, args] of MUST_BLOCK) {
    it(`analyzeInstallCommand blocks: ${manager} ${args.join(" ")}`, () => {
      const analysis = analyzeInstallCommand(manager, args, FEED);
      expect(analysis.blocked).toBe(true);
      expect(analysis.specs.map((s) => s.name)).toContain(EVIL);
    });

    it(`runInstallGuard does not spawn: ${manager} ${args.join(" ")}`, () => {
      const spy = spawnSpy();
      const code = runInstallGuard(manager, args, { feed: FEED, spawn: spy.fn, log: vi.fn() });
      expect(code).toBe(2);
      expect(spy.calls).toEqual([]);
    });
  }

  it("a value flag value is still not read as a package (negative control)", () => {
    const a = analyzeInstallCommand("npm", ["exec", "--cache", "evilpkg-cache", "lodash"], FEED);
    expect(a.specs.map((s) => s.name)).toEqual(["lodash"]);
    expect(a.blocked).toBe(false);
    const b = analyzeInstallCommand("npm", ["install", "--save-exact", "lodash"], FEED);
    expect(b.specs.map((s) => s.name)).toEqual(["lodash"]);
    expect(b.blocked).toBe(false);
  });

  it("arguments for the executed command are not misreported as packages", () => {
    const a = analyzeInstallCommand("pnpm", ["dlx", "cowsay", EVIL], FEED);
    expect(a.specs.map((s) => s.name)).toEqual(["cowsay"]);
    expect(a.blocked).toBe(false);
  });

  it("verbs that install nothing new still pass through", () => {
    expect(analyzeInstallCommand("pnpm", ["run", "dlx"], FEED).installVerb).toBe(false);
    expect(analyzeInstallCommand("npm", ["ci"], FEED).installVerb).toBe(false);
  });
});

describe("F30: a line break in a guarded argument is refused before any spawn", () => {
  for (const arg of ["a\nb&echo>MARKER", "a\rb", "lodash\r\n"]) {
    it(`refuses ${JSON.stringify(arg)}`, () => {
      const spy = spawnSpy();
      const log = vi.fn();
      const code = runInstallGuard("npm", ["install", arg], { feed: FEED, spawn: spy.fn, log });
      expect(code).toBe(2);
      expect(spy.calls).toEqual([]);
      expect(log.mock.calls.flat().join("\n")).toMatch(/line break/);
    });
  }

  it("a clean argument still spawns", () => {
    const spy = spawnSpy();
    expect(runInstallGuard("npm", ["install", "lodash"], { feed: FEED, spawn: spy.fn, log: vi.fn() })).toBe(0);
    expect(spy.calls).toEqual([["install", "lodash"]]);
  });
});
