/**
 * Go module supply-chain scanner.
 *
 * Detects supply-chain risks in go.mod, go.sum, and Go source files
 * (particularly init() functions).
 */


import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
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
// Go-specific patterns
// ---------------------------------------------------------------------------

interface GoStructuralMatch {
  start: number;
  end: number;
  evidence: string;
}

type GoMatchRange = Pick<GoStructuralMatch, "start" | "end">;

function goStructuralMatch(
  content: string,
  start: number,
  end: number,
): GoStructuralMatch {
  return {
    start,
    end,
    evidence: content.slice(
      start,
      Math.min(end, start + MAX_CORRELATED_EVIDENCE_CHARS),
    ),
  };
}

function* matchGoLines(
  content: string,
  findMatch: (line: string) => GoMatchRange | undefined,
): Iterable<GoStructuralMatch> {
  let lineStart = 0;
  while (lineStart <= content.length) {
    const newline = content.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? content.length : newline;
    const line = content.slice(lineStart, lineEnd);
    const match = findMatch(line);
    if (match) {
      yield goStructuralMatch(
        content,
        lineStart + match.start,
        lineStart + match.end,
      );
    }
    if (newline === -1) break;
    lineStart = newline + 1;
  }
}

function preferGoMatch(
  current: GoMatchRange | undefined,
  candidate: GoMatchRange,
): GoMatchRange {
  if (!current || candidate.start < current.start) return candidate;
  if (candidate.start === current.start && candidate.end > current.end) {
    return candidate;
  }
  return current;
}

function isGoAsciiWord(value: string | undefined): boolean {
  return value !== undefined && /[A-Za-z0-9_]/.test(value);
}

function makeGoInitMatcher(
  sinkPattern: string,
): NonNullable<PatternEntry["correlatedMatcher"]> {
  return (content) =>
    matchGoLines(content, (line) => {
      const tokens = new RegExp(
        `func\\s+init\\s*\\(\\s*\\)|(?:${sinkPattern})|\\}`,
        "gi",
      );
      let initStart = -1;
      let best: GoMatchRange | undefined;
      let token: RegExpExecArray | null;

      while ((token = tokens.exec(line)) !== null) {
        if (token[0] === "}") {
          initStart = -1;
        } else if (/^func/i.test(token[0]!)) {
          if (initStart === -1) initStart = token.index;
        } else if (initStart !== -1) {
          best = preferGoMatch(best, {
            start: initStart,
            end: tokens.lastIndex,
          });
        }
      }
      return best;
    });
}

const goInitExecMatcher = makeGoInitMatcher("exec\\.Command");
const goInitNetworkMatcher = makeGoInitMatcher(
  "http\\.(?:Get|Post|NewRequest)|net\\.Dial",
);

const goEnvExfilMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = (content) =>
  matchGoLines(content, (line) => {
    const tokens = /os\.Getenv|http\.|net\.Dial|[\r\u2028\u2029]/gi;
    const httpMethod = /(?:Post|Get|NewRequest)/iy;
    let forwardEnv = -1;
    let reverseNetwork = -1;
    let best: GoMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      if (/^[\r\u2028\u2029]$/u.test(value)) {
        forwardEnv = -1;
        reverseNetwork = -1;
      } else if (/^os\.Getenv$/i.test(value)) {
        // As in the Cargo rule, only the forward alternative has a boundary.
        if (reverseNetwork !== -1) {
          best = preferGoMatch(best, {
            start: reverseNetwork,
            end: tokens.lastIndex,
          });
        }
        if (
          forwardEnv === -1 &&
          !isGoAsciiWord(line[tokens.lastIndex])
        ) {
          forwardEnv = token.index;
        }
      } else {
        if (forwardEnv !== -1) {
          best = preferGoMatch(best, {
            start: forwardEnv,
            end: tokens.lastIndex,
          });
        }

        let reverseEligible = /^net\.Dial$/i.test(value);
        if (!reverseEligible) {
          httpMethod.lastIndex = tokens.lastIndex;
          reverseEligible = httpMethod.exec(line) !== null;
        }
        if (reverseEligible && reverseNetwork === -1) {
          reverseNetwork = token.index;
        }
      }
    }
    return best;
  });
export const GO_PATTERNS: PatternEntry[] = [
  // go.mod risks
  {
    name: "go-replace-directive",
    pattern:
      "replace\\s+\\S+\\s+=?>?\\s+\\S+",
    description:
      "Go module replace directive detected. Replaces redirect dependency resolution to alternate sources.",
    severity: "high",
    rule: "GO_REPLACE_DIRECTIVE",
  },
  {
    name: "go-retract-directive",
    pattern:
      "retract\\s+",
    description:
      "Go module retract directive. Retractions can hide previously published malicious versions.",
    severity: "medium",
    rule: "GO_RETRACT_DIRECTIVE",
  },

  // Go source risks (init functions)
  {
    name: "go-init-exec",
    pattern:
      "func\\s+init\\s*\\(\\s*\\)[^}]*exec\\.Command",
    description:
      "Go init() function executes system commands. init() runs automatically on package import.",
    severity: "high",
    rule: "GO_INIT_EXEC",
    correlatedMatcher: goInitExecMatcher,
  },
  {
    name: "go-init-network",
    pattern:
      "func\\s+init\\s*\\(\\s*\\)[^}]*(?:http\\.(?:Get|Post|NewRequest)|net\\.Dial)",
    description:
      "Go init() function makes network requests. init() runs automatically on package import.",
    severity: "medium",
    rule: "GO_INIT_NETWORK",
    correlatedMatcher: goInitNetworkMatcher,
  },

  // General Go source risks
  {
    name: "go-cgo-import",
    pattern:
      'import\\s+"C"',
    description:
      "CGo import detected. CGo enables arbitrary C code execution and bypasses Go's memory safety.",
    severity: "medium",
    rule: "GO_CGO_IMPORT",
  },
  {
    name: "go-unsafe-import",
    pattern:
      'import\\s+"unsafe"',
    description:
      "unsafe package imported. Unsafe code bypasses Go's type system and memory safety guarantees.",
    severity: "low",
    rule: "GO_UNSAFE_IMPORT",
  },
  {
    name: "go-plugin-load",
    pattern:
      "plugin\\.Open\\s*\\(",
    description:
      "Go plugin loaded dynamically. Plugins execute arbitrary code at runtime.",
    severity: "high",
    rule: "GO_PLUGIN_LOAD",
  },
  {
    name: "go-os-exec",
    pattern:
      "os/exec|exec\\.Command\\s*\\(",
    description:
      "System command execution via os/exec.",
    severity: "medium",
    rule: "GO_OS_EXEC",
  },
  {
    name: "go-env-exfil",
    pattern:
      "os\\.Getenv\\b.*(?:http\\.|net\\.Dial)|(?:http\\.(?:Post|Get|NewRequest)|net\\.Dial).*os\\.Getenv",
    description:
      "Environment variable access combined with network requests (potential exfiltration).",
    severity: "high",
    rule: "GO_ENV_EXFIL",
    correlatedMatcher: goEnvExfilMatcher,
  },
];

validatePatternSet("GO_PATTERNS", GO_PATTERNS);

/** Go-related file patterns */
const GO_MOD = "go.mod";
const GO_SUM = "go.sum";

/**
 * Check if a file is a Go-related config file.
 */
export function isGoFile(filename: string): boolean {
  return filename === GO_MOD || filename === GO_SUM || filename.endsWith(".go");
}

/**
 * Scan Go module files in a directory.
 */
export function scanGoFiles(dir: string): Finding[] {
  const findings: Finding[] = [];

  // Scan go.mod
  const goMod = readOptionalUtf8File(
    dir,
    path.join(dir, GO_MOD),
    GO_MOD,
    findings,
  );
  if (goMod !== null) {
    findings.push(...scanGoContent(goMod, GO_MOD, "mod"));
  }

  // Scan go.sum (resolved module inventory) for malicious modules
  const goSum = readOptionalUtf8File(
    dir,
    path.join(dir, GO_SUM),
    GO_SUM,
    findings,
  );
  if (goSum !== null) {
    findings.push(...scanGoSumContent(goSum, GO_SUM));
  }

  // Preserve the historical module gate: standalone Go source is handled by
  // the main file scanner, while this pass owns module-specific source checks.
  if (goMod === null && goSum === null) return findings;

  // Scan .go files in root and common source dirs
  scanGoSourceDir(dir, dir, ".", findings);
  scanGoSourceDir(dir, path.join(dir, "cmd"), "cmd", findings);
  scanGoSourceDir(dir, path.join(dir, "internal"), "internal", findings);
  scanGoSourceDir(dir, path.join(dir, "pkg"), "pkg", findings);

  return findings;
}

/**
 * Scan content of a Go-related file.
 */
export function scanGoContent(
  content: string,
  relativePath: string,
  fileType: "mod" | "source",
): Finding[] {
  const findings: Finding[] = [];

  const patterns =
    fileType === "mod"
      ? GO_PATTERNS.filter(
          (p) => p.rule === "GO_REPLACE_DIRECTIVE" || p.rule === "GO_RETRACT_DIRECTIVE",
        )
      : GO_PATTERNS.filter(
          (p) => p.rule !== "GO_REPLACE_DIRECTIVE" && p.rule !== "GO_RETRACT_DIRECTIVE",
        );

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
        match: goTruncate(hit.text),
        recommendation: getGoRecommendation(pattern.rule),
      });
    }
  }

  return findings;
}

/**
 * Scan go.sum for modules matching curated threat-intel IOCs (go: prefixed
 * feed entries). go.sum lines are "module version hash" or
 * "module version/go.mod hash"; both carry the same module@version, so each
 * module is reported once regardless of how many hash lines it has.
 */
export function scanGoSumContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();
  const seen = new Set<string>();
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const parts = (lines[i] ?? "").trim().split(/\s+/);
    if (parts.length < 2) continue;
    const module = parts[0] ?? "";
    // The second field is "v1.2.3" or "v1.2.3/go.mod"; keep only the version.
    const version = (parts[1] ?? "").replace(/\/go\.mod$/, "");
    if (!module || !version) continue;

    const key = `${module}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const ioc = matchPackageIOC("go", module, version, iocFeed);
    if (ioc) {
      findings.push(maliciousModuleFinding(module, version, ioc, relativePath, i + 1));
    }
  }

  return findings;
}

function maliciousModuleFinding(
  module: string,
  version: string,
  ioc: FeedIOC,
  relativePath: string,
  line: number,
): Finding {
  return {
    rule: "GO_MALICIOUS_MODULE",
    description: `Known malicious Go module: ${module}@${version}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
    severity: ioc.severity,
    file: relativePath,
    line,
    match: goTruncate(`${module}@${version}`),
    confidence: ioc.confidence,
    category: "malware",
    recommendation: `Remove ${module} immediately, rotate any credentials available to `
      + "`go build`, and audit systems that built it. This module is listed in threat intelligence feeds.",
  };
}

function goTruncate(value: string): string {
  return value.length > 120 ? value.substring(0, 120) + "..." : value;
}

/**
 * Scan .go files in a directory (non-recursive, single level).
 */
function scanGoSourceDir(
  scanRoot: string,
  dir: string,
  relativeDir: string,
  findings: Finding[],
): void {
  const entries = listOptionalDirectory(scanRoot, dir, relativeDir, findings);
  if (entries === null) return;

  for (const entry of entries) {
    if ((!entry.isFile() && !entry.isSymbolicLink()) || !entry.name.endsWith(".go")) continue;

    const relPath = relativeDir === "."
      ? entry.name
      : `${relativeDir}/${entry.name}`;
    const content = readDiscoveredUtf8File(
      scanRoot,
      path.join(dir, entry.name),
      relPath,
      findings,
    );
    if (content === null) continue;
    findings.push(...scanGoContent(content, relPath, "source"));
  }
}

function getGoRecommendation(rule: string): string {
  const map: Record<string, string> = {
    GO_REPLACE_DIRECTIVE:
      "Verify replace directives point to trusted sources. Replaces can redirect modules to malicious code.",
    GO_RETRACT_DIRECTIVE:
      "Check retracted versions for security implications.",
    GO_INIT_EXEC:
      "Audit init() command execution. init() runs automatically on import and can execute arbitrary commands.",
    GO_INIT_NETWORK:
      "init() functions should not make network requests. This runs automatically on every import.",
    GO_CGO_IMPORT:
      "CGo allows arbitrary C code. Audit the C code for vulnerabilities or malicious behavior.",
    GO_UNSAFE_IMPORT:
      "Review unsafe package usage. It bypasses Go's type and memory safety.",
    GO_PLUGIN_LOAD:
      "Dynamic plugin loading executes arbitrary code. Verify the plugin source is trusted.",
    GO_OS_EXEC:
      "Review system command execution for injection risks.",
    GO_ENV_EXFIL:
      "Environment variable access combined with network requests is a data exfiltration pattern.",
  };
  return map[rule] ?? "Review this Go code manually.";
}
