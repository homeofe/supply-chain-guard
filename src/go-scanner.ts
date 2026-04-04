/**
 * Go module supply-chain scanner.
 *
 * Detects supply-chain risks in go.mod, go.sum, and Go source files
 * (particularly init() functions).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";

// ---------------------------------------------------------------------------
// Go-specific patterns
// ---------------------------------------------------------------------------

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
  },
  {
    name: "go-init-network",
    pattern:
      "func\\s+init\\s*\\(\\s*\\)[^}]*(?:http\\.(?:Get|Post|NewRequest)|net\\.Dial)",
    description:
      "Go init() function makes network requests. init() runs automatically on package import.",
    severity: "medium",
    rule: "GO_INIT_NETWORK",
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
  },
];

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
  const goMod = path.join(dir, GO_MOD);
  if (fs.existsSync(goMod)) {
    try {
      const content = fs.readFileSync(goMod, "utf-8");
      findings.push(...scanGoContent(content, GO_MOD, "mod"));
    } catch { /* skip */ }
  }

  // Scan .go files in root and common source dirs
  scanGoSourceDir(dir, findings);
  const cmdDir = path.join(dir, "cmd");
  if (fs.existsSync(cmdDir)) scanGoSourceDir(cmdDir, findings);
  const internalDir = path.join(dir, "internal");
  if (fs.existsSync(internalDir)) scanGoSourceDir(internalDir, findings);
  const pkgDir = path.join(dir, "pkg");
  if (fs.existsSync(pkgDir)) scanGoSourceDir(pkgDir, findings);

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
  const lines = content.split("\n");

  const patterns =
    fileType === "mod"
      ? GO_PATTERNS.filter(
          (p) => p.rule === "GO_REPLACE_DIRECTIVE" || p.rule === "GO_RETRACT_DIRECTIVE",
        )
      : GO_PATTERNS.filter(
          (p) => p.rule !== "GO_REPLACE_DIRECTIVE" && p.rule !== "GO_RETRACT_DIRECTIVE",
        );

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.pattern, "i");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = regex.exec(line);
      if (match) {
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match:
            match[0].length > 120
              ? match[0].substring(0, 120) + "..."
              : match[0],
          recommendation: getGoRecommendation(pattern.rule),
        });
      }
    }
  }

  return findings;
}

/**
 * Scan .go files in a directory (non-recursive, single level).
 */
function scanGoSourceDir(dir: string, findings: Finding[]): void {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".go")) continue;

      const fullPath = path.join(dir, entry.name);
      const relPath = path.relative(process.cwd(), fullPath).replace(/\\/g, "/");

      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        findings.push(...scanGoContent(content, relPath, "source"));
      } catch { /* skip */ }
    }
  } catch { /* skip */ }
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
