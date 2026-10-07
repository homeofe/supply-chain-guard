/**
 * Resolve external tools (git, tar, gh, a package manager) to an absolute path
 * before running them.
 *
 * Passing a bare name to child_process lets the OS decide which file runs. On
 * Windows both cmd.exe and libuv look in the CURRENT DIRECTORY before PATH, so
 * `execSync("git ...", { cwd: scanDir })` ran a `git.bat` shipped inside the
 * scanned package. On POSIX an empty or relative PATH entry does the same.
 * The scanner's whole input is untrusted, so the lookup is done here, from
 * absolute PATH entries only, and the child receives the absolute path.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import {
  execFileSync,
  type ExecFileSyncOptions,
  type ExecFileSyncOptionsWithStringEncoding,
} from "node:child_process";

export interface ResolveExecutableOptions {
  /** Defaults to process.env. */
  env?: NodeJS.ProcessEnv;
  /** Defaults to process.platform. Tests only. */
  platform?: NodeJS.Platform;
  /**
   * Accept .cmd/.bat matches on Windows. They can only run through cmd.exe,
   * so only a caller that does its own cmd.exe quoting (the install guard)
   * sets this. Default false: such a match is skipped and the search goes on.
   */
  allowShellScripts?: boolean;
}

const WINDOWS_DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD";
const WINDOWS_SHELL_SCRIPT = /\.(?:cmd|bat)$/i;

function envValue(env: NodeJS.ProcessEnv, name: string, platform: NodeJS.Platform): string | undefined {
  if (platform !== "win32") return env[name];
  // Windows environment names are case-insensitive ("Path" is common).
  const key = Object.keys(env).find((k) => k.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

function isRunnableFile(candidate: string, platform: NodeJS.Platform): boolean {
  try {
    if (!fs.statSync(candidate).isFile()) return false;
    if (platform !== "win32") fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Absolute path of `name` from the absolute entries of PATH, or undefined.
 * Empty and relative PATH entries are skipped, and the current directory is
 * never searched implicitly. `name` must be a bare file name.
 */
export function resolveExecutable(name: string, options: ResolveExecutableOptions = {}): string | undefined {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const p = platform === "win32" ? path.win32 : path.posix;
  if (name.length === 0 || name !== p.basename(name) || name.includes("/") || name.includes("\\")) {
    return undefined;
  }

  const dirs = (envValue(env, "PATH", platform) ?? "")
    .split(platform === "win32" ? ";" : ":")
    .map((d) => (platform === "win32" ? d.trim().replace(/^"(.*)"$/, "$1") : d))
    .filter((d) => d.length > 0 && p.isAbsolute(d) && (platform !== "win32" || /^(?:[A-Za-z]:[\\/]|\\\\)/.test(d)));

  let names = [name];
  if (platform === "win32") {
    const exts = (envValue(env, "PATHEXT", platform) || WINDOWS_DEFAULT_PATHEXT)
      .split(";")
      .map((e) => e.trim().toLowerCase())
      .filter((e) => /^\.[a-z0-9]+$/.test(e));
    const own = p.extname(name).toLowerCase();
    // A name with a known extension is taken as is; otherwise try each
    // PATHEXT extension in order, as Windows does. The extensionless file is
    // never tried: npm ships a POSIX shell script named plain `npm`.
    names = own && exts.includes(own) ? [name] : exts.map((e) => name + e);
    if (!options.allowShellScripts) names = names.filter((n) => !WINDOWS_SHELL_SCRIPT.test(n));
  }

  for (const dir of dirs) {
    for (const candidate of names) {
      const full = p.join(dir, candidate);
      if (isRunnableFile(full, platform)) return full;
    }
  }
  return undefined;
}

/**
 * Child environment for an internal tool run: on Windows it also tells any
 * cmd.exe or CreateProcess lookup BELOW the tool not to search the current
 * directory first.
 */
export function hardenedChildEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  if (process.platform !== "win32") return env;
  return { ...env, NoDefaultCurrentDirectoryInExePath: "1" };
}

/**
 * execFileSync for a tool given by bare name: resolved through
 * resolveExecutable, never through a shell. Throws an ENOENT error when the
 * tool is not on PATH, which every caller already treats as "tool missing".
 */
export function execToolSync(name: string, args: readonly string[], options: ExecFileSyncOptionsWithStringEncoding): string;
export function execToolSync(name: string, args: readonly string[], options?: ExecFileSyncOptions): Buffer;
export function execToolSync(
  name: string,
  args: readonly string[],
  options: ExecFileSyncOptions = {},
): string | Buffer {
  const resolved = resolveExecutable(name, { env: options.env ?? process.env });
  if (!resolved) {
    const err = new Error(`${name}: not found on PATH`) as NodeJS.ErrnoException;
    err.code = "ENOENT";
    throw err;
  }
  return execFileSync(resolved, args, { ...options, shell: false, env: hardenedChildEnv(options.env ?? process.env) });
}
