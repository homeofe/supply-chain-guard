/**
 * Threat-feed npm IOCs in every lockfile format, including TRANSITIVE
 * dependencies.
 *
 * Before this, a whole-name (bare) feed entry fired only on package.json, so a
 * malicious package pulled in transitively was reported by NOTHING; and
 * yarn.lock, pnpm-lock.yaml and bun.lock were matched against the small
 * hand-kept KNOWN_BAD_NPM_VERSIONS list only, never against the feed.
 * Measured on 2026-09-23 with a real `scan`, see STATUS.md.
 *
 * Entries come from the live bundle, like lockfile-pinned-ioc.test.ts, so the
 * tests keep exercising real data as the feed grows.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { getBundledFeed } from "../threat-intel.js";
import { checkBadVersion } from "../ioc-blocklist.js";
import { lockfileFeedFindings, manifestReportedNames } from "../lockfile-feed.js";

const feed = getBundledFeed();

function pick() {
  let pinned: { name: string; version: string } | undefined;
  let bare: string | undefined;
  for (const ioc of feed) {
    if (ioc.type !== "package" || ioc.value.includes(":") || ioc.value.startsWith("@")) continue;
    const at = ioc.value.lastIndexOf("@");
    if (at > 0) {
      const cand = { name: ioc.value.slice(0, at), version: ioc.value.slice(at + 1) };
      if (!pinned && /^\d+\.\d+\.\d+$/.test(cand.version) && checkBadVersion(cand.name, cand.version, "npm") === null) {
        pinned = cand;
      }
    } else if (!bare && /^[a-z0-9][a-z0-9-]*$/.test(ioc.value)) {
      bare = ioc.value;
    }
    if (pinned && bare) break;
  }
  if (!pinned || !bare) throw new Error("feed lacks a feed-only pinned and a bare npm entry");
  return { pinned, bare };
}

const { pinned, bare } = pick();
const SRI = `sha512-${"A".repeat(86)}==`;

let tmpRoot: string;
beforeAll(() => { tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "scg-lockfeed-")); });
afterAll(() => { if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true }); });

type Dep = { name: string; version: string };

function lockfile(kind: "npm" | "yarn" | "pnpm" | "bun", deps: Dep[]): [string, string] {
  switch (kind) {
    case "npm":
      return ["package-lock.json", JSON.stringify({
        name: "fx", version: "1.0.0", lockfileVersion: 3,
        packages: Object.fromEntries([
          ["", { name: "fx", version: "1.0.0" }],
          ...deps.map((d) => [`node_modules/${d.name}`, { version: d.version, resolved: `https://registry.npmjs.org/${d.name}/-/x.tgz`, integrity: SRI }]),
          // The same package nested under another dependency: must still be ONE finding.
          ...deps.map((d) => [`node_modules/some-parent/node_modules/${d.name}`, { version: d.version, resolved: `https://registry.npmjs.org/${d.name}/-/x.tgz`, integrity: SRI }]),
        ]),
      })];
    case "yarn":
      return ["yarn.lock", ["# yarn lockfile v1", "", ...deps.flatMap((d) => [
        `${d.name}@^${d.version}:`, `  version "${d.version}"`,
        `  resolved "https://registry.yarnpkg.com/${d.name}/-/${d.name}-${d.version}.tgz#abc"`, `  integrity ${SRI}`, "",
      ])].join("\n")];
    case "pnpm":
      return ["pnpm-lock.yaml", ["lockfileVersion: '9.0'", "", "packages:", "", ...deps.flatMap((d) => [
        `  ${d.name}@${d.version}:`, `    resolution: {integrity: ${SRI}}`, "",
      ])].join("\n")];
    case "bun":
      return ["bun.lock", JSON.stringify({
        lockfileVersion: 1,
        workspaces: { "": { name: "fx" } },
        packages: Object.fromEntries(deps.map((d) => [d.name, [`${d.name}@${d.version}`, "", {}, SRI]])),
      }, null, 2)];
  }
}

function project(id: string, kind: "npm" | "yarn" | "pnpm" | "bun", deps: Dep[], direct: Record<string, string> = {}): string {
  const dir = path.join(tmpRoot, id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "fx", version: "1.0.0", dependencies: direct }));
  const [file, content] = lockfile(kind, deps);
  fs.writeFileSync(path.join(dir, file), content);
  return dir;
}

const rules = (r: { findings: { rule: string; match?: string }[] }, rule: string) =>
  r.findings.filter((f) => f.rule === rule);

describe.each(["npm", "yarn", "pnpm", "bun"] as const)("%s lockfile", (kind) => {
  it("reports a TRANSITIVE whole-name malicious package, once", async () => {
    const r = await scan({ target: project(`${kind}-bare`, kind, [{ name: bare, version: "1.2.3" }]), format: "json", noHistory: true });
    const found = rules(r, "LOCKFILE_MALICIOUS_PACKAGE");
    expect(found).toHaveLength(1);
    expect(found[0]?.match).toBe(`${bare}@1.2.3`);
  });

  it("reports a pinned malicious version", async () => {
    const r = await scan({ target: project(`${kind}-pinned`, kind, [pinned]), format: "json", noHistory: true });
    expect(rules(r, "LOCKFILE_MALICIOUS_VERSION")).toHaveLength(1);
  });

  // The manifest already reports a DIRECT dependency (MALICIOUS_DEPENDENCY);
  // the lockfile must not report the same package a second time.
  it("does not double-report a direct dependency the manifest already reports", async () => {
    const r = await scan({
      target: project(`${kind}-direct`, kind, [{ name: bare, version: "1.2.3" }], { [bare]: "^1.0.0" }),
      format: "json", noHistory: true,
    });
    expect(rules(r, "MALICIOUS_DEPENDENCY")).toHaveLength(1);
    expect(rules(r, "LOCKFILE_MALICIOUS_PACKAGE")).toEqual([]);
  });

  it("leaves a clean tree alone", async () => {
    const r = await scan({
      target: project(`${kind}-clean`, kind, [{ name: "lodash", version: "4.17.21" }, { name: "chalk", version: "5.3.0" }]),
      format: "json", noHistory: true,
    });
    expect(rules(r, "LOCKFILE_MALICIOUS_PACKAGE")).toEqual([]);
    expect(rules(r, "LOCKFILE_MALICIOUS_VERSION")).toEqual([]);
  });
});

describe("manifestReportedNames", () => {
  it("returns the INSTALLED name for an npm alias, as the manifest check does", () => {
    const names = manifestReportedNames(JSON.stringify({
      dependencies: { utils: "npm:real-target@1.0.0", plain: "^2.0.0" },
      devDependencies: { dev: "1.0.0" },
      optionalDependencies: { opt: "1.0.0" },
      peerDependencies: { peer: "1.0.0" },
    }));
    expect([...names].sort()).toEqual(["dev", "opt", "peer", "plain", "real-target"]);
  });

  // An unparseable manifest reports nothing, so nothing may be skipped either.
  it("skips nothing when the manifest cannot be parsed", () => {
    expect(manifestReportedNames("{ not json").size).toBe(0);
    expect(manifestReportedNames(null).size).toBe(0);
  });
});

describe("lockfileFeedFindings", () => {
  it("defers to the hand-kept blocklist, which already reports that dependency", () => {
    // A package-version present in KNOWN_BAD_NPM_VERSIONS is reported as
    // IOC_KNOWN_BAD_VERSION by the lockfile checkers; no second feed finding.
    const blocklisted = feed
      .filter((i) => i.type === "package" && !i.value.includes(":") && i.value.lastIndexOf("@") > 0)
      .map((i) => ({ name: i.value.slice(0, i.value.lastIndexOf("@")), version: i.value.slice(i.value.lastIndexOf("@") + 1) }))
      .find((d) => checkBadVersion(d.name, d.version, "npm") !== null);
    expect(blocklisted).toBeDefined();
    expect(lockfileFeedFindings([blocklisted!], "yarn.lock", new Set(), feed)).toEqual([]);
  });
});
