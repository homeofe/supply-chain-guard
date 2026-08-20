/**
 * T-016: version-pinned npm IOCs now match on a directory scan.
 *
 * The feed is mostly version-pinned, and those entries were reachable through
 * `guard` but not through `scan` - the more visible surface. The fix lives in
 * the lockfile path because that is the only place a RESOLVED version exists;
 * a package.json dependency value is a range, not a version.
 *
 * Entries are discovered from the live feed rather than hardcoded, so these
 * keep testing the real thing as the feed grows by 100-200 entries per sweep.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { getBundledFeed } from "../threat-intel.js";
import { checkBadVersion } from "../ioc-blocklist.js";

const RULE = "LOCKFILE_MALICIOUS_VERSION";
const feed = getBundledFeed();

/**
 * One npm entry of each shape, taken from the live feed.
 *
 * The pinned pick deliberately SKIPS anything KNOWN_BAD_NPM_VERSIONS already
 * covers. Those produce IOC_KNOWN_BAD_VERSION and the feed finding is suppressed
 * on purpose, so using one here would test the dedup rather than the new rule.
 * The first pinned entry in the feed is axios@1.14.1, which is exactly such a
 * case - this cost a debugging round to notice.
 */
function pick() {
  let pinned: { name: string; version: string } | undefined;
  let alsoBlocklisted: { name: string; version: string } | undefined;
  let bare: string | undefined;
  for (const ioc of feed) {
    if (ioc.type !== "package" || ioc.value.includes(":")) continue;
    const at = ioc.value.lastIndexOf("@");
    if (at > 0) {
      const cand = { name: ioc.value.slice(0, at), version: ioc.value.slice(at + 1) };
      const covered = checkBadVersion(cand.name, cand.version, "npm") !== null;
      if (covered) { if (!alsoBlocklisted) alsoBlocklisted = cand; }
      else if (!pinned) pinned = cand;
    } else if (!bare) {
      bare = ioc.value;
    }
    if (pinned && bare && alsoBlocklisted) break;
  }
  if (!pinned || !bare || !alsoBlocklisted) {
    throw new Error("feed lacks a feed-only pinned entry, a blocklisted one, and a bare one");
  }
  return { pinned, bare, alsoBlocklisted };
}

const { pinned, bare, alsoBlocklisted } = pick();

let tmpRoot: string;
beforeAll(() => { tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "scg-t016-")); });
afterAll(() => { if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true }); });

/** A project whose lockfile resolves the given name to the given version. */
function project(id: string, deps: Record<string, string>, shape: "v2" | "v1" = "v2"): string {
  const dir = path.join(tmpRoot, id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "fx", version: "1.0.0", dependencies: {} }),
  );

  const lock: Record<string, unknown> =
    shape === "v2"
      ? {
          name: "fx", version: "1.0.0", lockfileVersion: 3, requires: true,
          packages: Object.fromEntries([
            ["", { name: "fx", version: "1.0.0" }],
            ...Object.entries(deps).map(([n, v]) => [
              `node_modules/${n}`,
              { version: v, resolved: `https://registry.npmjs.org/${n}/-/x.tgz`, integrity: "sha512-AAAA" },
            ]),
          ]),
        }
      : {
          name: "fx", version: "1.0.0", lockfileVersion: 1,
          dependencies: Object.fromEntries(
            Object.entries(deps).map(([n, v]) => [n, { version: v, resolved: "https://registry.npmjs.org/x", integrity: "sha512-AAAA" }]),
          ),
        };

  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(lock, null, 2));
  return dir;
}

const hits = (f: { rule: string }[]) => f.filter((x) => x.rule === RULE);

describe("pinned feed IOCs match a resolved lockfile version", () => {
  it("fires on the exact pinned version (lockfile v2/v3)", async () => {
    const dir = project("hit-v2", { [pinned.name]: pinned.version });
    const r = await scan({ target: dir, format: "json" });
    const found = hits(r.findings);

    expect(found).toHaveLength(1);
    expect(found[0].severity).toBe("critical");
    expect(found[0].match).toBe(`${pinned.name}@${pinned.version}`);
    expect(found[0].file).toBe("package-lock.json");
  });

  it("fires on the v1 lockfile shape too", async () => {
    const dir = project("hit-v1", { [pinned.name]: pinned.version }, "v1");
    const r = await scan({ target: dir, format: "json" });
    expect(hits(r.findings)).toHaveLength(1);
  });

  it("does NOT fire on a different version of the same package", async () => {
    // The whole safety argument is that this is exact equality. If a near-miss
    // version fires, the false-positive surface is not what was measured.
    const dir = project("miss", { [pinned.name]: "0.0.0-definitely-not-the-pinned-one" });
    const r = await scan({ target: dir, format: "json" });
    expect(hits(r.findings)).toEqual([]);
  });

  it("does NOT double-report a bare-name entry from the lockfile", async () => {
    // Bare-name entries match any version and already fire on the package.json
    // path. A lockfile lists every transitive dependency, so reporting them here
    // too would multiply one finding across the tree.
    const dir = project("bare", { [bare]: "1.2.3" });
    const r = await scan({ target: dir, format: "json" });
    expect(hits(r.findings)).toEqual([]);
  });

  it("leaves an ordinary dependency tree clean", async () => {
    const dir = project("clean", { lodash: "4.17.21", chalk: "5.3.0", semver: "7.6.0" });
    const r = await scan({ target: dir, format: "json" });
    expect(hits(r.findings)).toEqual([]);
  });

  it("emits one finding per dependency for a package in BOTH sources", async () => {
    // The blocklist is the more specific source, so it wins and the feed finding
    // is suppressed. Without that, every dependency present in both would be
    // reported twice.
    const dir = project("dup", { [alsoBlocklisted.name]: alsoBlocklisted.version });
    const r = await scan({ target: dir, format: "json" });

    const blocklist = r.findings.filter((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
    expect(blocklist).toHaveLength(1);
    expect(hits(r.findings)).toEqual([]);
  });
});
