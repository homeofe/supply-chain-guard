/**
 * Where the threat-feed and catalog caches live.
 *
 * The default used to be `.scg-cache` in the WORKING directory. Two things
 * followed from that. A `feed refresh` run in one directory was invisible to a
 * scan started from any other, which then matched without the catalog and said
 * so only in an informational finding. And a scan started from inside the
 * checkout under scan read a cache that checkout could commit: the Action
 * already isolates its cache for exactly that reason (action.yml, and
 * action-partial-scan.test.ts), the CLI did not.
 *
 * The default is now one directory per user, the platform's cache location:
 *
 *   1. `--cache-dir <dir>` (the `explicit` argument)
 *   2. the `SCG_CACHE_DIR` environment variable
 *   3. Windows: `%LOCALAPPDATA%\supply-chain-guard\cache`
 *      macOS:   `~/Library/Caches/supply-chain-guard`
 *      others:  `$XDG_CACHE_HOME/supply-chain-guard`, else
 *               `~/.cache/supply-chain-guard`
 *   4. no home directory at all: `.scg-cache` in the working directory, the
 *      old default, so a process without a home still has a cache
 */

import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";

/** The former default, relative to the working directory. */
export const LEGACY_CACHE_DIR = ".scg-cache";

export interface CacheDirContext {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  homedir?: string;
}

function home(ctx: CacheDirContext): string {
  if (ctx.homedir !== undefined) return ctx.homedir;
  try {
    return os.homedir();
  } catch {
    return "";
  }
}

/** An environment value that names a usable absolute directory, or undefined. */
function absoluteEnv(value: string | undefined, platform: NodeJS.Platform): string | undefined {
  if (!value || value.trim() === "") return undefined;
  const p = platform === "win32" ? path.win32 : path.posix;
  return p.isAbsolute(value) ? value : undefined;
}

/** The per-user default cache directory, or undefined when there is no home. */
export function userCacheDir(ctx: CacheDirContext = {}): string | undefined {
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const h = home(ctx);

  if (platform === "win32") {
    const local = absoluteEnv(env.LOCALAPPDATA, platform);
    if (local) return path.win32.join(local, "supply-chain-guard", "cache");
    return h ? path.win32.join(h, "AppData", "Local", "supply-chain-guard", "cache") : undefined;
  }
  if (platform === "darwin") {
    return h ? path.posix.join(h, "Library", "Caches", "supply-chain-guard") : undefined;
  }
  const xdg = absoluteEnv(env.XDG_CACHE_HOME, platform);
  if (xdg) return path.posix.join(xdg, "supply-chain-guard");
  return h ? path.posix.join(h, ".cache", "supply-chain-guard") : undefined;
}

/** The cache directory a command uses, in the order documented above. */
export function resolveCacheDir(explicit?: string, ctx: CacheDirContext = {}): string {
  if (explicit !== undefined && explicit !== "") return explicit;
  const env = ctx.env ?? process.env;
  const fromEnv = env.SCG_CACHE_DIR;
  if (fromEnv !== undefined && fromEnv.trim() !== "") return fromEnv;
  return userCacheDir(ctx) ?? LEGACY_CACHE_DIR;
}

/**
 * A cache path as it may appear in a report. Reports are published (SARIF in
 * code scanning, JSON artifacts), and a per-user path carries the account
 * name, so the home directory is replaced by `~`. A path outside the home
 * directory is left as it is: the caller chose it.
 */
export function displayCachePath(p: string, ctx: CacheDirContext = {}): string {
  const h = home(ctx);
  if (!h) return p;
  const platform = ctx.platform ?? process.platform;
  const sep = platform === "win32" ? "\\" : "/";
  const norm = (s: string) => (platform === "win32" ? s.toLowerCase().replace(/\//g, "\\") : s);
  const hp = norm(h).replace(/[\\/]+$/, "");
  const pp = norm(p);
  if (pp === hp) return "~";
  if (pp.startsWith(hp + sep)) return "~" + sep + p.slice(hp.length + 1);
  return p;
}

/**
 * Whether the working directory still holds a cache in the former location
 * that the selected cache path does not read.
 */
export function legacyCacheIgnored(explicit?: string, ctx: CacheDirContext = {}, cwd: string = process.cwd()): boolean {
  const used = path.resolve(cwd, resolveCacheDir(explicit, ctx));
  const legacy = path.resolve(cwd, LEGACY_CACHE_DIR);
  const samePath = (ctx.platform ?? process.platform) === "win32"
    ? used.toLowerCase() === legacy.toLowerCase()
    : used === legacy;
  if (samePath) return false;
  try {
    return fs.statSync(legacy).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The note `feed refresh` prints when it wrote somewhere other than a `.scg-cache` that still
 * sits in the working directory, or null when there is nothing to say.
 *
 * Before 6.4.0 a refresh wrote `.scg-cache/threat-feed.json` in the working directory, and CI
 * steps were written to check that file after refreshing. Since the move such a step fails
 * with "missing or empty" right after a successful refresh, and nothing in the refresh output
 * connected the two. The catalog finding already names an ignored `.scg-cache`, but only a
 * scan reaches it; a pipeline that checks the file first never gets there.
 */
export function legacyRefreshNote(explicit?: string, ctx: CacheDirContext = {}, cwd: string = process.cwd()): string | null {
  if (!legacyCacheIgnored(explicit, ctx, cwd)) return null;
  return (
    `  Note: a ${LEGACY_CACHE_DIR} directory exists in the working directory, but since 6.4.0 the\n` +
    `  refresh used ${displayCachePath(resolveCacheDir(explicit, ctx), ctx)}, so it was not written there.\n` +
    `  To keep using it, pass --cache-dir ${LEGACY_CACHE_DIR} or set SCG_CACHE_DIR=${LEGACY_CACHE_DIR}.`
  );
}
