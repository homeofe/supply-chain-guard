/**
 * Cargo/Rust supply-chain scanner.
 *
 * Detects supply-chain risks in Cargo.toml, build.rs, and
 * Rust procedural macros.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";

// ---------------------------------------------------------------------------
// Cargo/Rust patterns
// ---------------------------------------------------------------------------

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
  },
  {
    name: "cargo-build-rs-env-exfil",
    pattern:
      "env::var\\b.*(?:reqwest|hyper|TcpStream|UdpSocket)|(?:reqwest|hyper|TcpStream|UdpSocket).*env::var",
    description:
      "build.rs reads environment variables near network code (potential data exfiltration).",
    severity: "critical",
    rule: "CARGO_BUILD_RS_ENV_EXFIL",
  },
  {
    name: "cargo-build-rs-download",
    pattern:
      "(?:curl|wget|fetch|download).*(?:write_all|copy|save|File::create)",
    description:
      "build.rs downloads and writes files to disk.",
    severity: "high",
    rule: "CARGO_BUILD_RS_DOWNLOAD",
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

/** Cargo-related file names */
const CARGO_FILES = new Set(["Cargo.toml", "Cargo.lock"]);
const BUILD_RS = "build.rs";

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
  const cargoToml = path.join(dir, "Cargo.toml");
  if (fs.existsSync(cargoToml)) {
    try {
      const content = fs.readFileSync(cargoToml, "utf-8");
      findings.push(...scanCargoContent(content, "Cargo.toml", "toml"));
    } catch { /* skip */ }
  }

  // Scan build.rs
  const buildRs = path.join(dir, BUILD_RS);
  if (fs.existsSync(buildRs)) {
    try {
      const content = fs.readFileSync(buildRs, "utf-8");
      findings.push(...scanCargoContent(content, BUILD_RS, "build"));
    } catch { /* skip */ }
  }

  // Scan proc-macro crates (look in src/ for files with proc_macro attribute)
  scanProcMacros(dir, findings);

  return findings;
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
  const lines = content.split("\n");

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
          recommendation: getCargoRecommendation(pattern.rule),
        });
      }
    }
  }

  return findings;
}

/**
 * Look for proc-macro source files and scan them.
 */
function scanProcMacros(dir: string, findings: Finding[]): void {
  // Check if Cargo.toml declares proc-macro = true
  const cargoToml = path.join(dir, "Cargo.toml");
  if (!fs.existsSync(cargoToml)) return;

  let tomlContent: string;
  try {
    tomlContent = fs.readFileSync(cargoToml, "utf-8");
  } catch {
    return;
  }

  if (!tomlContent.includes("proc-macro") && !tomlContent.includes("proc_macro")) return;

  // Scan .rs files in src/
  const srcDir = path.join(dir, "src");
  if (!fs.existsSync(srcDir)) return;

  try {
    const entries = fs.readdirSync(srcDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".rs")) continue;

      const fullPath = path.join(srcDir, entry.name);
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        const relPath = `src/${entry.name}`;
        findings.push(...scanCargoContent(content, relPath, "proc-macro"));
      } catch { /* skip */ }
    }
  } catch { /* skip */ }
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
