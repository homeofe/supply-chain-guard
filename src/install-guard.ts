/**
 * Install-time guard (v5.5, roadmap Bet 2).
 *
 * Blocks known-bad packages BEFORE the package manager runs their lifecycle
 * scripts: `supply-chain-guard guard npm install <pkg>` checks every package
 * spec on the command line against the OFFLINE IOC sources (bundled threat
 * feed + refreshed .scg-cache feed + known-bad-version blocklist + typosquat
 * heuristics) and only invokes the real package manager when nothing matches.
 *
 * Everything is auditable in git history, works offline, needs no account.
 * No network calls are made by this module.
 */

import { spawnSync } from "node:child_process";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { checkBadVersion } from "./ioc-blocklist.js";
import { analyzeDependencyRisks } from "./dependency-risk-analyzer.js";
import type { Finding } from "./types.js";

// ---------------------------------------------------------------------------
// Managers and install verbs
// ---------------------------------------------------------------------------

export const SUPPORTED_MANAGERS = ["npm", "pnpm", "yarn", "bun"] as const;
export type PackageManager = (typeof SUPPORTED_MANAGERS)[number];

/**
 * Verbs that add NEW package specs from the command line. Verbs missing here
 * (npm ci, yarn install, run, test, ...) either install nothing new or take
 * their inputs from manifest/lockfile - those are covered by `scan`, not by
 * the install guard, and pass through unchanged.
 */
const INSTALL_VERBS: Record<PackageManager, ReadonlySet<string>> = {
  // npm accepts a long list of documented aliases/typo-forms for `install`
  // (npm-install(1)): a guard that silently no-ops on `npm isntall evil` gives
  // false assurance. v5.6.0 gate finding M2.
  npm: new Set([
    "install", "add", "i", "in", "ins", "inst", "insta", "instal",
    "isnt", "isnta", "isntal", "isntall",
  ]),
  pnpm: new Set(["add", "install", "i"]),
  yarn: new Set(["add"]),
  bun: new Set(["add", "install", "i", "a"]),
};

// Flags that consume the NEXT token as their value. Their value must not be
// mistaken for the install verb or a package spec (v5.6.0 gate finding M3 and
// its low-severity sibling: `npm --prefix ./x install evil` and
// `npm install --prefix x lodash`).
const VALUE_FLAGS = new Set([
  "--prefix", "-C", "--dir", "--cwd", "--registry", "--tag", "--workspace",
  "-w", "--store-dir", "--cache", "--config", "--userconfig", "--globalconfig",
  "--loglevel", "--network-timeout", "--filter", "--reporter", "--save-exact",
]);

function isPackageManager(manager: string): manager is PackageManager {
  return (SUPPORTED_MANAGERS as readonly string[]).includes(manager);
}

/**
 * The four managers are shipped as .cmd shims on Windows; spawn needs the
 * shim name there. The platform parameter exists for tests only.
 */
export function resolveManagerBinary(
  manager: PackageManager,
  platform: NodeJS.Platform = process.platform,
): string {
  return platform === "win32" ? `${manager}.cmd` : manager;
}

// ---------------------------------------------------------------------------
// Spec extraction
// ---------------------------------------------------------------------------

export interface InstallPackageSpec {
  /** Token exactly as given on the command line */
  raw: string;
  /** Package name ("lodash", "@scope/name") */
  name: string;
  /** Version/range/tag after the last "@", if present ("1.2.3", "^1.0.0", "latest") */
  version?: string;
}

/**
 * Registry package name shape (optionally scoped). Anything else on the
 * command line - paths, tarballs, git/URL/alias specs - cannot be resolved
 * against the offline blocklist and is left for the full `scan` to judge.
 */
const REGISTRY_NAME_RE = /^(@[a-z0-9][a-z0-9-._~]*\/)?[a-z0-9-._~][a-z0-9-._~]*$/i;

/**
 * Parse one command-line token into a package spec. Returns null for flags
 * and for tokens that are not plain registry specs.
 */
export function parseSpecToken(token: string): InstallPackageSpec | null {
  if (token.length === 0 || token.startsWith("-")) return null;

  // Split "name@version" / "@scope/name@version" at the LAST "@";
  // index 0 is the scope marker, not a version separator.
  const at = token.lastIndexOf("@");
  const name = at > 0 ? token.substring(0, at) : token;
  const version = at > 0 ? token.substring(at + 1) : undefined;

  if (!REGISTRY_NAME_RE.test(name)) return null;
  // Protocol versions ("foo@npm:bar@1.0.0" aliases, "foo@git:...") are not
  // plain registry pins; skip rather than mis-attribute a version.
  if (version !== undefined && (version.length === 0 || version.includes(":"))) return null;

  return version === undefined ? { raw: token, name } : { raw: token, name, version };
}

/**
 * Extract package specs from manager args.
 *
 * The install verb is the first bare token that IS a known install verb,
 * found by scanning positionally while skipping flags, flag values, and the
 * `global` positional modifier. This defeats two confirmed bypasses (v5.6.0
 * gate M3): a value-taking global flag shifting the apparent verb
 * (`npm --prefix ./x install evil`) and Yarn's `global add` form
 * (`yarn global add evil`). If no install verb is present the command
 * installs nothing new and passes through unscanned.
 */
export function extractInstallSpecs(
  manager: PackageManager,
  args: string[],
): { verb?: string; installVerb: boolean; specs: InstallPackageSpec[] } {
  const verbs = INSTALL_VERBS[manager];
  let verbIdx = -1;
  let verb: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.length === 0) continue;
    if (a.startsWith("-")) {
      // `--flag value` form: skip the value so it is never read as the verb.
      if (VALUE_FLAGS.has(a) && i + 1 < args.length) i++;
      continue;
    }
    if (verb === undefined) verb = a; // first bare token, for reporting
    if (verbs.has(a)) { verbIdx = i; verb = a; break; }
    // `global` is a positional modifier (npm/yarn `global add`), not the verb.
    if (a === "global") continue;
    // A different bare token before any install verb (run, ci, exec, a script
    // name, ...): not an install command, stop.
    break;
  }

  if (verbIdx === -1) return { verb, installVerb: false, specs: [] };

  const specs: InstallPackageSpec[] = [];
  const rest = args.slice(verbIdx + 1);
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (token.startsWith("-")) {
      if (VALUE_FLAGS.has(token) && i + 1 < rest.length) i++; // skip flag value
      continue;
    }
    const spec = parseSpecToken(token);
    if (spec) specs.push(spec);
  }
  return { verb, installVerb: true, specs };
}

// ---------------------------------------------------------------------------
// Offline analysis
// ---------------------------------------------------------------------------

export interface InstallGuardVerdict {
  spec: InstallPackageSpec;
  findings: Finding[];
}

export interface InstallCommandAnalysis {
  manager: PackageManager;
  /** First non-flag manager arg (undefined when args are all flags/empty) */
  verb?: string;
  /** True when the verb adds new packages from the command line */
  installVerb: boolean;
  specs: InstallPackageSpec[];
  /** One verdict per spec; findings empty = clean */
  verdicts: InstallGuardVerdict[];
  /** True when at least one spec has findings */
  blocked: boolean;
}

/**
 * npm package IOCs in the feed carry no ecosystem prefix (only ruby:/composer:/
 * nuget:/go:/jenkins: entries do - see matchPackageIOC). Same companion
 * matcher as mcp-server.ts matchBarePackageIOC.
 */
function matchBareNpmIOC(
  name: string,
  version: string | undefined,
  feed: FeedIOC[],
): FeedIOC | null {
  for (const ioc of feed) {
    if (ioc.type !== "package") continue;
    // Skip ecosystem-prefixed entries; npm names never contain ":".
    if (ioc.value.includes(":")) continue;

    const at = ioc.value.lastIndexOf("@");
    const iocName = at > 0 ? ioc.value.substring(0, at) : ioc.value;
    const iocVersion = at > 0 ? ioc.value.substring(at + 1) : undefined;

    if (iocName !== name) continue;
    if (iocVersion === undefined) return ioc; // bare-name IOC: any version
    if (version !== undefined && iocVersion === version) return ioc;
  }
  return null;
}

function checkSpec(spec: InstallPackageSpec, feed: FeedIOC[]): Finding[] {
  const findings: Finding[] = [];

  // 1. Threat-intel package IOCs (bundled + refreshed .scg-cache feed).
  const ioc =
    matchPackageIOC("npm", spec.name, spec.version, feed) ??
    matchBareNpmIOC(spec.name, spec.version, feed);
  if (ioc) {
    findings.push({
      rule: "THREAT_INTEL_PACKAGE_IOC",
      description: `Package IOC match: ${ioc.value}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
      severity: ioc.severity,
      file: spec.raw,
      confidence: ioc.confidence,
      category: "malware",
      recommendation: `Do not install ${spec.raw}. This package is listed in the threat-intel feed${ioc.campaign ? ` (campaign: ${ioc.campaign})` : ""}.`,
    });
  }

  // 2. Known-bad version blocklist (needs an exact version pin to match).
  if (spec.version !== undefined) {
    const bad = checkBadVersion(spec.name, spec.version, "npm");
    if (bad) findings.push({ ...bad, file: spec.raw });
  }

  // 3. Typosquat / internal-name heuristics, reused from the dependency risk
  //    analyzer (Levenshtein distance against popular packages).
  findings.push(
    ...analyzeDependencyRisks({ [spec.name]: spec.version ?? "*" }, spec.raw),
  );

  return findings;
}

/**
 * Pure analysis of an install command: no spawn, no network, no filesystem
 * writes (loadThreatIntel reads the local feed cache when no feed is given).
 */
export function analyzeInstallCommand(
  manager: string,
  args: string[],
  feed?: FeedIOC[],
): InstallCommandAnalysis {
  if (!isPackageManager(manager)) {
    throw new Error(
      `Unsupported package manager "${manager}". Allowed: ${SUPPORTED_MANAGERS.join(", ")}. ` +
        "The install guard never executes arbitrary commands.",
    );
  }

  const { verb, installVerb, specs } = extractInstallSpecs(manager, args);
  if (!installVerb || specs.length === 0) {
    return { manager, verb, installVerb, specs, verdicts: [], blocked: false };
  }

  const entries = feed ?? loadThreatIntel();
  const verdicts = specs.map((spec) => ({ spec, findings: checkSpec(spec, entries) }));
  const blocked = verdicts.some((v) => v.findings.length > 0);

  return { manager, verb, installVerb, specs, verdicts, blocked };
}

// ---------------------------------------------------------------------------
// Guarded execution
// ---------------------------------------------------------------------------

/** Injectable spawn signature - tests replace this so nothing is executed. */
export type SpawnLike = (
  command: string,
  args: string[],
  options: { stdio: "inherit"; shell: false },
) => { status: number | null; error?: Error };

// cmd.exe metacharacters that must be ^-escaped (cross-spawn's meta set).
const CMD_META_RE = /([()\][%!^"`<>&|;, *?])/g;

/**
 * ^-escape a bare command name for cmd.exe (never quoted). The .cmd/.bat shim
 * re-expands the whole line through cmd once more via `%*`, so metacharacters
 * must be ^-escaped TWICE (doubleEscapeMetaChars in cross-spawn). Single
 * escaping is a command-injection hole: v5.6.0 gate finding M1 proved
 * `x"&echo INJECTED&"` broke out during the %* re-parse with one escape and
 * did not with two.
 */
export function escapeCmdShellCommand(command: string): string {
  // Two passes, not "^^$1": the second pass must also escape the `^` chars the
  // first pass introduced (cross-spawn doubleEscapeMetaChars semantics).
  return command.replace(CMD_META_RE, "^$1").replace(CMD_META_RE, "^$1");
}

/**
 * Quote + double-^-escape one argument for cmd.exe (cross-spawn technique for
 * .cmd/.bat targets): backslash-double the sequences before quotes, wrap in
 * double quotes, then ^-escape every cmd metacharacter twice because the shim
 * re-parses the line. See escapeCmdShellCommand for why two passes.
 */
export function escapeCmdShellArg(arg: string): string {
  let escaped = arg.replace(/(\\*)"/g, '$1$1\\"');
  escaped = escaped.replace(/(\\*)$/, "$1$1");
  return `"${escaped}"`.replace(CMD_META_RE, "^$1").replace(CMD_META_RE, "^$1");
}

/**
 * Node >=20.12 (CVE-2024-27980 hardening) refuses to spawn .cmd/.bat files
 * with shell:false (EINVAL), and npm/pnpm/yarn ship as .cmd shims on Windows.
 * The default spawn therefore routes .cmd shims through `cmd.exe /d /s /c`
 * with windowsVerbatimArguments and full metacharacter escaping (the
 * cross-spawn technique) - every argument is individually quoted and
 * ^-escaped, never naively concatenated, and the command name itself comes
 * from the fixed four-manager allowlist. Everywhere else the manager is
 * spawned directly without any shell.
 */
const defaultSpawn: SpawnLike = (command, args, options) => {
  if (process.platform === "win32" && command.toLowerCase().endsWith(".cmd")) {
    const commandLine = [escapeCmdShellCommand(command), ...args.map(escapeCmdShellArg)].join(" ");
    const result = spawnSync(
      process.env.comspec ?? "cmd.exe",
      ["/d", "/s", "/c", `"${commandLine}"`],
      { stdio: options.stdio, windowsVerbatimArguments: true },
    );
    return { status: result.status, error: result.error };
  }
  const result = spawnSync(command, args, options);
  return { status: result.status, error: result.error };
};

export interface InstallGuardOptions {
  /** Proceed despite findings (loud warning). */
  force?: boolean;
  /** Check only; never invoke the package manager. */
  dryRun?: boolean;
  /** Injected feed (tests); defaults to loadThreatIntel(). */
  feed?: FeedIOC[];
  /** Injected spawn (tests); defaults to node:child_process spawnSync. */
  spawn?: SpawnLike;
  /** Injected output sink; defaults to console.log. */
  log?: (line: string) => void;
}

function printVerdicts(analysis: InstallCommandAnalysis, log: (line: string) => void): void {
  const hits = analysis.verdicts.filter((v) => v.findings.length > 0);
  const total = hits.reduce((n, v) => n + v.findings.length, 0);
  log("");
  log(`  Install guard: ${total} finding(s) in "${analysis.manager} ${analysis.verb}" command:`);
  for (const verdict of hits) {
    log("");
    log(`  Package: ${verdict.spec.raw}`);
    for (const finding of verdict.findings) {
      log(`    [${finding.severity.toUpperCase()}] ${finding.rule}: ${finding.description}`);
      log(`    ${finding.recommendation}`);
    }
  }
  log("");
}

/**
 * Analyze the command, print findings, and (unless blocked or --dry-run)
 * invoke the package manager with the args untouched. Returns the process
 * exit code: manager's own code on pass-through, 2 when blocked, 0 for a
 * clean --dry-run.
 *
 * Execution is spawn-without-shell on every platform; the manager name is
 * restricted to the four known binaries, so no shell string is ever built
 * from user input.
 */
export function runInstallGuard(
  manager: string,
  managerArgs: string[],
  options: InstallGuardOptions = {},
): number {
  const spawnFn = options.spawn ?? defaultSpawn;
  const log = options.log ?? ((line: string) => console.log(line));

  const analysis = analyzeInstallCommand(manager, managerArgs, options.feed);

  if (analysis.blocked) {
    printVerdicts(analysis, log);
    if (options.dryRun) {
      log("  Dry run: package manager not invoked.");
      return 2;
    }
    if (!options.force) {
      log(`  BLOCKED: ${analysis.manager} was not invoked. Re-run with --force to override (not recommended).`);
      return 2;
    }
    log("  WARNING: --force is set - proceeding DESPITE the findings above. The packages listed are known-bad or suspicious.");
  } else if (options.dryRun) {
    log(
      `  Install guard: no known-bad packages in "${[analysis.manager, ...managerArgs].join(" ")}" (dry run, nothing executed).`,
    );
    return 0;
  }

  const binary = resolveManagerBinary(analysis.manager);
  const result = spawnFn(binary, managerArgs, { stdio: "inherit", shell: false });
  if (result.error) {
    throw new Error(`Failed to run ${binary}: ${result.error.message}`);
  }
  return result.status ?? 1;
}
