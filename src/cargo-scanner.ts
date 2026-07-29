/**
 * Cargo/Rust supply-chain scanner.
 *
 * Detects supply-chain risks in Cargo.toml, build.rs, and
 * Rust procedural macros.
 */


import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { checkBadVersion } from "./ioc-blocklist.js";
import {
  listOptionalDirectory,
  matchPatternInFile,
  readDiscoveredUtf8File,
  readOptionalUtf8File,
} from "./pattern-scanner.js";
import {
  MAX_CORRELATED_EVIDENCE_CHARS,
  validatePatternSet,
} from "./patterns.js";

// ---------------------------------------------------------------------------
// Cargo/Rust patterns
// ---------------------------------------------------------------------------

interface CargoStructuralMatch {
  start: number;
  end: number;
  evidence: string;
}

type CargoMatchRange = Pick<CargoStructuralMatch, "start" | "end">;

function cargoStructuralMatch(
  content: string,
  start: number,
  end: number,
): CargoStructuralMatch {
  return {
    start,
    end,
    evidence: content.slice(
      start,
      Math.min(end, start + MAX_CORRELATED_EVIDENCE_CHARS),
    ),
  };
}

function* matchCargoLines(
  content: string,
  findMatch: (line: string) => CargoMatchRange | undefined,
): Iterable<CargoStructuralMatch> {
  let lineStart = 0;
  while (lineStart <= content.length) {
    const newline = content.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? content.length : newline;
    const line = content.slice(lineStart, lineEnd);
    const match = findMatch(line);
    if (match) {
      yield cargoStructuralMatch(
        content,
        lineStart + match.start,
        lineStart + match.end,
      );
    }
    if (newline === -1) break;
    lineStart = newline + 1;
  }
}

function isDotTerminator(value: string): boolean {
  return /^[\r\u2028\u2029]$/u.test(value);
}

function isAsciiWord(value: string | undefined): boolean {
  return value !== undefined && /[A-Za-z0-9_]/.test(value);
}

function preferCargoMatch(
  current: CargoMatchRange | undefined,
  candidate: CargoMatchRange,
): CargoMatchRange {
  if (!current || candidate.start < current.start) return candidate;
  if (candidate.start === current.start && candidate.end > current.end) {
    return candidate;
  }
  return current;
}

const cargoBuildNetworkMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = (content) =>
  matchCargoLines(content, (line) => {
    const tokens =
      /(?:reqwest|hyper|curl|ureq|attohttpc|minreq)\b|get|post|request|fetch|TcpStream::connect|[\r\u2028\u2029]/gi;
    const sourceToken = /^(?:reqwest|hyper|curl|ureq|attohttpc|minreq)$/i;
    let sourceStart = -1;
    let firstTcp = -1;
    let bestCorrelated: CargoMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      if (isDotTerminator(value)) {
        sourceStart = -1;
      } else if (/^TcpStream::connect$/i.test(value)) {
        if (firstTcp === -1) firstTcp = token.index;
      } else if (sourceToken.test(value)) {
        if (sourceStart === -1) sourceStart = token.index;
      } else if (sourceStart !== -1) {
        bestCorrelated = preferCargoMatch(bestCorrelated, {
          start: sourceStart,
          end: tokens.lastIndex,
        });
      }
    }

    const standalone = firstTcp === -1
      ? undefined
      : { start: firstTcp, end: firstTcp + "TcpStream::connect".length };
    if (!standalone) return bestCorrelated;
    return preferCargoMatch(bestCorrelated, standalone);
  });

const cargoBuildEnvExfilMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = (content) =>
  matchCargoLines(content, (line) => {
    const tokens =
      /env::var|reqwest|hyper|TcpStream|UdpSocket|[\r\u2028\u2029]/gi;
    let forwardEnv = -1;
    let reverseNetwork = -1;
    let best: CargoMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      if (isDotTerminator(value)) {
        forwardEnv = -1;
        reverseNetwork = -1;
      } else if (/^env::var$/i.test(value)) {
        // The reverse legacy alternative ends in env::var without a boundary,
        // while the forward alternative requires env::var\b.
        if (reverseNetwork !== -1) {
          best = preferCargoMatch(best, {
            start: reverseNetwork,
            end: tokens.lastIndex,
          });
        }
        if (
          forwardEnv === -1 &&
          !isAsciiWord(line[tokens.lastIndex])
        ) {
          forwardEnv = token.index;
        }
      } else {
        if (forwardEnv !== -1) {
          best = preferCargoMatch(best, {
            start: forwardEnv,
            end: tokens.lastIndex,
          });
        }
        if (reverseNetwork === -1) reverseNetwork = token.index;
      }
    }
    return best;
  });

const cargoBuildDownloadMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = (content) =>
  matchCargoLines(content, (line) => {
    const tokens =
      /curl|wget|fetch|download|write_all|copy|save|File::create|[\r\u2028\u2029]/gi;
    let sourceStart = -1;
    let best: CargoMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      if (isDotTerminator(value)) {
        sourceStart = -1;
      } else if (/^(?:curl|wget|fetch|download)$/i.test(value)) {
        if (sourceStart === -1) sourceStart = token.index;
      } else if (sourceStart !== -1) {
        best = preferCargoMatch(best, {
          start: sourceStart,
          end: tokens.lastIndex,
        });
      }
    }
    return best;
  });
export const CARGO_PATTERNS: PatternEntry[] = [
  // build.rs risks
  {
    name: "cargo-build-rs-exec",
    pattern:
      "Command::new\\s*\\(|std::process::Command|process::Command",
    description:
      "build.rs executes system commands. Build scripts run during `cargo build` with full privileges.",
    severity: "critical",
    rule: "CARGO_BUILD_RS_EXEC",
  },
  {
    name: "cargo-build-rs-network",
    pattern:
      "(?:reqwest|hyper|curl|ureq|attohttpc|minreq)\\b.*(?:get|post|request|fetch)|TcpStream::connect",
    description:
      "build.rs performs network requests. Build scripts should not access the network.",
    severity: "high",
    rule: "CARGO_BUILD_RS_NETWORK",
    correlatedMatcher: cargoBuildNetworkMatcher,
  },
  {
    name: "cargo-build-rs-env-exfil",
    pattern:
      "env::var\\b.*(?:reqwest|hyper|TcpStream|UdpSocket)|(?:reqwest|hyper|TcpStream|UdpSocket).*env::var",
    description:
      "build.rs reads environment variables near network code (potential data exfiltration).",
    severity: "critical",
    rule: "CARGO_BUILD_RS_ENV_EXFIL",
    correlatedMatcher: cargoBuildEnvExfilMatcher,
  },
  {
    name: "cargo-build-rs-download",
    pattern:
      "(?:curl|wget|fetch|download).*(?:write_all|copy|save|File::create)",
    description:
      "build.rs downloads and writes files to disk.",
    severity: "high",
    rule: "CARGO_BUILD_RS_DOWNLOAD",
    correlatedMatcher: cargoBuildDownloadMatcher,
  },

  // Cargo.toml risks
  {
    name: "cargo-git-dependency",
    pattern:
      "git\\s*=\\s*[\"']https?://(?!github\\.com/rust-lang|github\\.com/tokio-rs|github\\.com/serde-rs)",
    description:
      "Cargo dependency from a git URL instead of crates.io. Git sources bypass crates.io integrity checks.",
    severity: "medium",
    rule: "CARGO_GIT_DEPENDENCY",
  },
  {
    name: "cargo-patch-section",
    pattern:
      "\\[patch\\.",
    description:
      "Cargo.toml [patch] section detected. Patches override crate sources and can redirect dependencies.",
    severity: "high",
    rule: "CARGO_PATCH_SECTION",
  },
  {
    name: "cargo-replace-section",
    pattern:
      "\\[replace\\]",
    description:
      "Cargo.toml [replace] section detected (deprecated). Replaces override dependency resolution.",
    severity: "high",
    rule: "CARGO_REPLACE_SECTION",
  },

  // Proc macro risks
  {
    name: "cargo-proc-macro-fs",
    pattern:
      "std::fs::|fs::(?:read|write|remove|create)",
    description:
      "Procedural macro performs file system operations. Proc macros run at compile time with full access.",
    severity: "high",
    rule: "CARGO_PROC_MACRO_FS",
  },
  {
    name: "cargo-proc-macro-network",
    pattern:
      "std::net::|TcpStream|UdpSocket|reqwest|hyper",
    description:
      "Procedural macro performs network operations. Proc macros should not access the network.",
    severity: "critical",
    rule: "CARGO_PROC_MACRO_NETWORK",
  },
];

validatePatternSet("CARGO_PATTERNS", CARGO_PATTERNS);

/** Cargo-related file names */
const CARGO_FILES = new Set(["Cargo.toml", "Cargo.lock"]);
const BUILD_RS = "build.rs";
const CARGO_LOCK = "Cargo.lock";

/**
 * Check if a file is a Cargo-related file.
 */
export function isCargoFile(filename: string): boolean {
  return CARGO_FILES.has(filename) || filename === BUILD_RS;
}

/**
 * Scan Cargo-related files in a directory.
 */
export function scanCargoFiles(dir: string): Finding[] {
  const findings: Finding[] = [];

  // Scan Cargo.toml
  const cargoToml = readOptionalUtf8File(
    dir,
    path.join(dir, "Cargo.toml"),
    "Cargo.toml",
    findings,
  );
  if (cargoToml !== null) {
    findings.push(...scanCargoContent(cargoToml, "Cargo.toml", "toml"));
  }

  // Scan build.rs
  const buildRs = readOptionalUtf8File(
    dir,
    path.join(dir, BUILD_RS),
    BUILD_RS,
    findings,
  );
  if (buildRs !== null) {
    findings.push(...scanCargoContent(buildRs, BUILD_RS, "build"));
  }

  // Scan Cargo.lock (resolved crate inventory) for malicious crates
  const cargoLock = readOptionalUtf8File(
    dir,
    path.join(dir, CARGO_LOCK),
    CARGO_LOCK,
    findings,
  );
  if (cargoLock !== null) {
    findings.push(...scanCargoLockContent(cargoLock, CARGO_LOCK));
  }

  // Scan proc-macro crates (look in src/ for files with proc_macro attribute)
  if (cargoToml !== null) scanProcMacros(dir, cargoToml, findings);

  return findings;
}

/**
 * Scan Cargo.lock for crates matching curated threat-intel IOCs (cargo:
 * prefixed feed entries) or known-compromised versions (ioc-blocklist).
 * Cargo.lock is TOML with flat [[package]] blocks (name = "x", version =
 * "y"); a hand-rolled line-state parser extracts name+version pairs without
 * adding a TOML dependency (same approach as the JS lockfile parsers).
 */
export function scanCargoLockContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();

  for (const { name, version } of parseCargoLock(content)) {
    // Threat-intel IOC match (bundled cargo: package entries)
    const ioc = matchPackageIOC("cargo", name, version, iocFeed);
    if (ioc) {
      findings.push(maliciousCrateFinding(name, version, ioc, relativePath));
    }

    // Known-compromised version (ioc-blocklist; cargo has no pinned entries
    // yet, but the check is wired so future entries match without a code change)
    if (version) {
      const bad = checkBadVersion(name, version, "cargo");
      if (bad) findings.push({ ...bad, file: relativePath });
    }
  }

  return findings;
}

interface CargoLockPackage {
  name: string;
  version?: string;
}

/**
 * Line-state parser for Cargo.lock [[package]] blocks. A new [[package]]
 * header (or any other table header) flushes the current block.
 */
function parseCargoLock(content: string): CargoLockPackage[] {
  const packages: CargoLockPackage[] = [];
  let current: CargoLockPackage | null = null;

  const flush = (): void => {
    if (current && current.name) packages.push(current);
    current = null;
  };

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (line === "[[package]]") {
      flush();
      current = { name: "" };
      continue;
    }
    // Any other table header ends the current package block (e.g. [metadata]).
    if (line.startsWith("[")) {
      flush();
      continue;
    }
    if (current === null) continue;

    const nameMatch = /^name\s*=\s*"([^"]+)"/.exec(line);
    if (nameMatch) {
      current.name = nameMatch[1]!;
      continue;
    }
    const versionMatch = /^version\s*=\s*"([^"]+)"/.exec(line);
    if (versionMatch) {
      current.version = versionMatch[1]!;
      continue;
    }
  }
  flush();
  return packages;
}

function maliciousCrateFinding(
  name: string,
  version: string | undefined,
  ioc: FeedIOC,
  relativePath: string,
): Finding {
  return {
    rule: "CARGO_MALICIOUS_CRATE",
    description: `Known malicious crate: ${name}${version ? `@${version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
    severity: ioc.severity,
    file: relativePath,
    match: truncate(version ? `${name}@${version}` : name),
    confidence: ioc.confidence,
    category: "malware",
    recommendation: `Remove ${name} immediately, rotate any credentials available to `
      + "`cargo build`, and audit systems that built it. This crate is listed in threat intelligence feeds.",
  };
}

function truncate(value: string): string {
  return value.length > 120 ? value.substring(0, 120) + "..." : value;
}

/**
 * Scan content of a Cargo-related file.
 */
export function scanCargoContent(
  content: string,
  relativePath: string,
  fileType: "toml" | "build" | "proc-macro",
): Finding[] {
  const findings: Finding[] = [];

  const patterns =
    fileType === "toml"
      ? CARGO_PATTERNS.filter((p) =>
          p.rule.startsWith("CARGO_GIT") ||
          p.rule.startsWith("CARGO_PATCH") ||
          p.rule.startsWith("CARGO_REPLACE"),
        )
      : fileType === "build"
        ? CARGO_PATTERNS.filter((p) => p.rule.startsWith("CARGO_BUILD_RS"))
        : CARGO_PATTERNS.filter((p) => p.rule.startsWith("CARGO_PROC_MACRO"));

  for (const pattern of patterns) {
    const hits = matchPatternInFile(
      pattern,
      content,
      relativePath,
      findings,
      "i",
    );
    for (const hit of hits ?? []) {
      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: relativePath,
        line: hit.line,
        match: truncate(hit.text),
        recommendation: getCargoRecommendation(pattern.rule),
      });
    }
  }

  return findings;
}

/**
 * Look for proc-macro source files and scan them.
 */
function scanProcMacros(
  dir: string,
  tomlContent: string,
  findings: Finding[],
): void {
  if (!tomlContent.includes("proc-macro") && !tomlContent.includes("proc_macro")) return;

  // Scan .rs files in src/
  const srcDir = path.join(dir, "src");
  const entries = listOptionalDirectory(dir, srcDir, "src", findings);
  if (entries === null) return;

  for (const entry of entries) {
    if ((!entry.isFile() && !entry.isSymbolicLink()) || !entry.name.endsWith(".rs")) continue;

    const relPath = `src/${entry.name}`;
    const content = readDiscoveredUtf8File(
      dir,
      path.join(srcDir, entry.name),
      relPath,
      findings,
    );
    if (content === null) continue;
    findings.push(...scanCargoContent(content, relPath, "proc-macro"));
  }
}

function getCargoRecommendation(rule: string): string {
  const map: Record<string, string> = {
    CARGO_BUILD_RS_EXEC:
      "Audit build.rs command execution. Build scripts run with full access during `cargo build`.",
    CARGO_BUILD_RS_NETWORK:
      "Build scripts should not make network requests. Use vendored dependencies or cargo's built-in mechanisms.",
    CARGO_BUILD_RS_ENV_EXFIL:
      "Environment variable access combined with network code in build.rs is a data exfiltration risk.",
    CARGO_BUILD_RS_DOWNLOAD:
      "Build script downloads files. Verify the source is trusted and integrity is checked.",
    CARGO_GIT_DEPENDENCY:
      "Use crates.io dependencies when possible. Git dependencies bypass registry integrity checks.",
    CARGO_PATCH_SECTION:
      "Verify [patch] entries are intentional. Patches override dependency resolution.",
    CARGO_REPLACE_SECTION:
      "The [replace] section is deprecated. Migrate to [patch] and audit the override.",
    CARGO_PROC_MACRO_FS:
      "Proc macros should not perform file I/O. They run at compile time with full file system access.",
    CARGO_PROC_MACRO_NETWORK:
      "Proc macros must not access the network. This is a strong indicator of a compromised crate.",
  };
  return map[rule] ?? "Review this Cargo configuration manually.";
}
