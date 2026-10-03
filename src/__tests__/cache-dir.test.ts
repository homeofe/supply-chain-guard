import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  LEGACY_CACHE_DIR,
  displayCachePath,
  legacyCacheIgnored,
  legacyRefreshNote,
  resolveCacheDir,
  userCacheDir,
} from "../cache-dir.js";
import { catalogFindings, CATALOG_MISSING_RULE } from "../feed.js";
import {
  FEED_CACHE_FILE,
  getDetectionSetProvenance,
  resetThreatIntelCache,
} from "../threat-intel.js";

// The threat-feed and catalog cache used to live in `.scg-cache` under the
// working directory, so a refresh in one directory was invisible to a scan
// started from another, and a scan started inside a checkout read a cache that
// checkout could commit. It is now one directory per user.

const linux = { platform: "linux" as const, homedir: "/home/alice" };
const mac = { platform: "darwin" as const, homedir: "/Users/alice" };
const win = { platform: "win32" as const, homedir: "C:\\Users\\alice" };

describe("resolveCacheDir", () => {
  it("prefers --cache-dir, then SCG_CACHE_DIR, then the per-user default", () => {
    const env = { SCG_CACHE_DIR: "/srv/scg" };
    expect(resolveCacheDir("/explicit", { ...linux, env })).toBe("/explicit");
    expect(resolveCacheDir(undefined, { ...linux, env })).toBe("/srv/scg");
    expect(resolveCacheDir(undefined, { ...linux, env: {} })).toBe("/home/alice/.cache/supply-chain-guard");
  });

  it("ignores an empty --cache-dir and an empty or blank SCG_CACHE_DIR", () => {
    expect(resolveCacheDir("", { ...linux, env: { SCG_CACHE_DIR: "" } })).toBe("/home/alice/.cache/supply-chain-guard");
    expect(resolveCacheDir(undefined, { ...linux, env: { SCG_CACHE_DIR: "  " } })).toBe("/home/alice/.cache/supply-chain-guard");
  });

  it("uses each platform's cache location", () => {
    expect(userCacheDir({ ...linux, env: { XDG_CACHE_HOME: "/var/cache/alice" } })).toBe("/var/cache/alice/supply-chain-guard");
    expect(userCacheDir({ ...mac, env: {} })).toBe("/Users/alice/Library/Caches/supply-chain-guard");
    expect(userCacheDir({ ...win, env: { LOCALAPPDATA: "D:\\Local" } })).toBe("D:\\Local\\supply-chain-guard\\cache");
    expect(userCacheDir({ ...win, env: {} })).toBe("C:\\Users\\alice\\AppData\\Local\\supply-chain-guard\\cache");
  });

  it("ignores a relative XDG_CACHE_HOME or LOCALAPPDATA, which would bring the working directory back", () => {
    expect(userCacheDir({ ...linux, env: { XDG_CACHE_HOME: "cache" } })).toBe("/home/alice/.cache/supply-chain-guard");
    expect(userCacheDir({ ...win, env: { LOCALAPPDATA: "Local" } })).toBe("C:\\Users\\alice\\AppData\\Local\\supply-chain-guard\\cache");
  });

  it("does not depend on the working directory", () => {
    for (const ctx of [linux, mac, win]) {
      const dir = resolveCacheDir(undefined, { ...ctx, env: {} });
      const p = ctx.platform === "win32" ? path.win32 : path.posix;
      expect(p.isAbsolute(dir), dir).toBe(true);
      expect(dir).not.toContain(LEGACY_CACHE_DIR);
    }
  });

  it("falls back to the former working-directory cache when there is no home at all", () => {
    expect(resolveCacheDir(undefined, { platform: "linux", homedir: "", env: {} })).toBe(LEGACY_CACHE_DIR);
    expect(resolveCacheDir(undefined, { platform: "win32", homedir: "", env: {} })).toBe(LEGACY_CACHE_DIR);
    // An absolute XDG_CACHE_HOME still works without a home.
    expect(resolveCacheDir(undefined, { platform: "linux", homedir: "", env: { XDG_CACHE_HOME: "/c" } })).toBe("/c/supply-chain-guard");
  });
});

describe("displayCachePath", () => {
  it("replaces the home directory, which carries the account name, with ~", () => {
    expect(displayCachePath("/home/alice/.cache/supply-chain-guard/threat-feed.json", linux)).toBe(
      "~/.cache/supply-chain-guard/threat-feed.json",
    );
    expect(displayCachePath("C:\\Users\\alice\\AppData\\Local\\supply-chain-guard\\cache\\threat-feed.json", win)).toBe(
      "~\\AppData\\Local\\supply-chain-guard\\cache\\threat-feed.json",
    );
    // Windows paths compare case-insensitively.
    expect(displayCachePath("c:\\users\\ALICE\\x.json", win)).toBe("~\\x.json");
  });

  it("leaves paths outside the home directory and look-alike prefixes unchanged", () => {
    expect(displayCachePath("/srv/scg/threat-feed.json", linux)).toBe("/srv/scg/threat-feed.json");
    expect(displayCachePath("/home/alice2/threat-feed.json", linux)).toBe("/home/alice2/threat-feed.json");
    expect(displayCachePath(".scg-cache/threat-feed.json", linux)).toBe(".scg-cache/threat-feed.json");
  });
});

describe("the scan report's provenance", () => {
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, SCG_CACHE_DIR: process.env.SCG_CACHE_DIR };
  let dir: string | undefined;

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    resetThreatIntelCache();
  });

  it("names a cache under the home directory without the account name", () => {
    dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "scg-home-")));
    process.env.HOME = dir;
    process.env.USERPROFILE = dir;
    const cache = path.join(dir, "cache");
    fs.mkdirSync(cache);
    fs.writeFileSync(
      path.join(cache, FEED_CACHE_FILE),
      JSON.stringify({ timestamp: new Date().toISOString(), entries: [] }),
    );
    process.env.SCG_CACHE_DIR = cache;
    resetThreatIntelCache();

    const provenance = getDetectionSetProvenance();
    expect(provenance.cacheMerged).toBe(true);
    expect(provenance.cachePath).toBe(`~${path.sep}cache${path.sep}${FEED_CACHE_FILE}`);
    expect(provenance.cachePath).not.toContain(dir);
  });
});

describe("a cache left in the working directory", () => {
  let cwd: string | undefined;
  afterEach(() => {
    if (cwd) fs.rmSync(cwd, { recursive: true, force: true });
    cwd = undefined;
  });

  it("is reported when the default no longer reads it", () => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cwd-"));
    fs.mkdirSync(path.join(cwd, LEGACY_CACHE_DIR));
    const ctx = { ...linux, env: {} };
    expect(legacyCacheIgnored(undefined, ctx, cwd)).toBe(true);
    // Named explicitly, or the default itself: nothing is being ignored.
    expect(legacyCacheIgnored(LEGACY_CACHE_DIR, ctx, cwd)).toBe(false);
    expect(legacyCacheIgnored(undefined, { platform: "linux", homedir: "", env: {} }, cwd)).toBe(false);
  });

  it("is not reported when there is none", () => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cwd-"));
    expect(legacyCacheIgnored(undefined, { ...linux, env: {} }, cwd)).toBe(false);
  });

  it("is named by feed refresh, with the default it wrote to and both ways to keep it", () => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cwd-"));
    fs.mkdirSync(path.join(cwd, LEGACY_CACHE_DIR));
    const ctx = { ...linux, env: {} };
    const note = legacyRefreshNote(undefined, ctx, cwd);
    expect(note).not.toBeNull();
    expect(note).toMatch(/\.scg-cache directory exists in the working directory/);
    expect(note).toMatch(/since 6\.4\.0/);
    expect(note).toContain("~/.cache/supply-chain-guard");
    expect(note).toContain("--cache-dir .scg-cache");
    expect(note).toContain("SCG_CACHE_DIR=.scg-cache");
    // The account name never appears: the home directory is shown as ~.
    expect(note).not.toContain("/home/alice");
  });

  it("is not named by feed refresh when the refresh wrote there or there is none", () => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cwd-"));
    const ctx = { ...linux, env: {} };
    expect(legacyRefreshNote(undefined, ctx, cwd)).toBeNull();
    fs.mkdirSync(path.join(cwd, LEGACY_CACHE_DIR));
    expect(legacyRefreshNote(LEGACY_CACHE_DIR, ctx, cwd)).toBeNull();
    expect(legacyRefreshNote(undefined, { ...linux, env: { SCG_CACHE_DIR: LEGACY_CACHE_DIR } }, cwd)).toBeNull();
  });

  it("is named in the catalog finding, with the way to keep using it", () => {
    const state = { available: false, reason: "absent" as const };
    const withHint = catalogFindings(state, "required", { legacyCacheInWorkingDir: true });
    const without = catalogFindings(state, "required");
    expect(withHint[0].rule).toBe(CATALOG_MISSING_RULE);
    expect(withHint[0].description).toMatch(/\.scg-cache directory in the working directory was not read/);
    expect(withHint[0].description).toMatch(/--cache-dir \.scg-cache/);
    expect(without[0].description).not.toMatch(/was not read/);
  });
});
