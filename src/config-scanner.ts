/**
 * Package manager configuration file scanner.
 *
 * Detects supply-chain risks in .npmrc, .yarnrc, .pnpmrc,
 * pip.conf, .pypirc, and pyproject.toml config files.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";

// ---------------------------------------------------------------------------
// Config patterns
// ---------------------------------------------------------------------------

export const CONFIG_PATTERNS: PatternEntry[] = [
  {
    name: "config-http-registry",
    pattern: "registry\\s*=\\s*http://(?!localhost|127\\.0\\.0\\.1)",
    description:
      "Package manager configured to use plain HTTP registry. Packages can be intercepted via MITM.",
    severity: "critical",
    rule: "CONFIG_HTTP_REGISTRY",
  },
  {
    name: "config-custom-registry",
    pattern:
      "registry\\s*=\\s*https?://(?!registry\\.npmjs\\.org|registry\\.yarnpkg\\.com|pypi\\.org|files\\.pythonhosted\\.org)",
    description:
      "Package manager points to a non-default registry. Verify this is intentional.",
    severity: "high",
    rule: "CONFIG_CUSTOM_REGISTRY",
  },
  {
    name: "config-auth-token",
    pattern:
      "(?:_authToken|_auth|_password|token|npm_token)\\s*=\\s*[A-Za-z0-9+/=_-]{8,}",
    description:
      "Authentication token found in config file. Tokens committed to version control can be stolen.",
    severity: "critical",
    rule: "CONFIG_AUTH_TOKEN_EXPOSED",
  },
  {
    name: "config-unsafe-perm",
    pattern: "unsafe-perm\\s*=\\s*true",
    description:
      "unsafe-perm=true allows install scripts to run as root, increasing attack surface.",
    severity: "medium",
    rule: "CONFIG_UNSAFE_PERM",
  },
  {
    name: "config-ignore-scripts-false",
    pattern: "ignore-scripts\\s*=\\s*false",
    description:
      "ignore-scripts explicitly set to false. Install scripts will execute on npm install.",
    severity: "low",
    rule: "CONFIG_IGNORE_SCRIPTS_OFF",
  },
  {
    name: "config-extra-index-url",
    pattern:
      "extra-index-url\\s*=\\s*https?://(?!pypi\\.org|files\\.pythonhosted\\.org)",
    description:
      "pip configured with extra-index-url pointing to a non-PyPI source. Dependency confusion risk.",
    severity: "high",
    rule: "CONFIG_EXTRA_INDEX",
  },
  {
    name: "config-pip-trusted-host",
    pattern: "trusted-host\\s*=",
    description:
      "pip trusted-host disables SSL verification for a host. Packages can be intercepted.",
    severity: "high",
    rule: "CONFIG_TRUSTED_HOST",
  },
];

/** Config file names to scan */
const CONFIG_FILES = new Set([
  ".npmrc",
  ".yarnrc",
  ".yarnrc.yml",
  ".pnpmrc",
  "pip.conf",
  ".pypirc",
]);

/**
 * Check whether a filename is a package manager config file.
 */
export function isConfigFile(filename: string): boolean {
  return CONFIG_FILES.has(filename);
}

/**
 * Scan a single config file for supply-chain risks.
 */
export function scanConfigFile(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (const pattern of CONFIG_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "i");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (line.trimStart().startsWith("#") || line.trimStart().startsWith(";"))
        continue; // skip comments
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
          recommendation: getConfigRecommendation(pattern.rule),
        });
      }
    }
  }

  return findings;
}

/**
 * Scan a directory for package manager config files.
 */
export function scanConfigFiles(dir: string): Finding[] {
  const findings: Finding[] = [];

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!isConfigFile(entry.name)) continue;

      const fullPath = path.join(dir, entry.name);
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        findings.push(...scanConfigFile(content, entry.name));
      } catch {
        // skip
      }
    }
  } catch {
    // directory not readable
  }

  return findings;
}

function getConfigRecommendation(rule: string): string {
  const map: Record<string, string> = {
    CONFIG_HTTP_REGISTRY:
      "Switch to HTTPS registry URL. HTTP registries allow man-in-the-middle attacks on packages.",
    CONFIG_CUSTOM_REGISTRY:
      "Verify this registry is trusted. Custom registries can serve tampered packages.",
    CONFIG_AUTH_TOKEN_EXPOSED:
      "Remove tokens from config files. Use environment variables (NPM_TOKEN) or credential managers.",
    CONFIG_UNSAFE_PERM:
      "Remove unsafe-perm=true. Running install scripts as root increases attack impact.",
    CONFIG_IGNORE_SCRIPTS_OFF:
      "Consider setting ignore-scripts=true and running build steps explicitly.",
    CONFIG_EXTRA_INDEX:
      "Verify the extra-index-url is trusted. Extra indexes enable dependency confusion attacks.",
    CONFIG_TRUSTED_HOST:
      "Remove trusted-host entries. Fix SSL certificate issues instead of bypassing verification.",
  };
  return map[rule] ?? "Review this configuration setting manually.";
}
