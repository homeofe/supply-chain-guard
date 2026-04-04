/**
 * Secret simulator / honeytoken system (v4.7).
 *
 * Provides fake credential files and environment variables for
 * sandboxed analysis. Detects if packages/scripts attempt to read
 * or exfiltrate them.
 */

import type { Finding } from "./types.js";

/** Simulated secret paths and their types */
const HONEYTOKEN_PATHS = [
  { path: ".npmrc", type: "npm token", marker: "npm_HONEYTOKEN_SCG_MARKER_12345678" },
  { path: ".env", type: "environment secrets", marker: "SCG_HONEY_SECRET=fake_credential_marker" },
  { path: ".ssh/id_rsa", type: "SSH private key", marker: "-----BEGIN RSA PRIVATE KEY-----\nSCG_HONEYTOKEN" },
  { path: ".aws/credentials", type: "AWS credentials", marker: "AKIASCGHONEYTOKEN1234" },
];

/** Simulated environment variables */
const HONEYTOKEN_ENV: Record<string, string> = {
  NPM_TOKEN: "npm_HONEYTOKEN_SCG_DETECT_EXFIL_0000",
  GITHUB_TOKEN: "ghp_SCGHoneytokenDetectExfiltration00",
  AWS_ACCESS_KEY_ID: "AKIASCGHONEYTOKEN1234",
  AWS_SECRET_ACCESS_KEY: "scg/honeytoken/detect/exfiltration/0000000000",
};

/**
 * Check if content references honeytoken markers.
 * This detects code that would attempt to read simulated secrets.
 */
export function checkHoneytokenAccess(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const honey of HONEYTOKEN_PATHS) {
    if (content.includes(honey.marker)) {
      findings.push({
        rule: "HONEYTOKEN_ACCESSED",
        description: `Honeytoken for ${honey.type} was accessed. Code attempted to read simulated credentials from ${honey.path}.`,
        severity: "critical",
        file: relativePath,
        confidence: 0.95,
        category: "malware",
        recommendation: "This code actively attempts to steal credentials. Quarantine immediately.",
      });
    }
  }

  for (const [envName, marker] of Object.entries(HONEYTOKEN_ENV)) {
    if (content.includes(marker)) {
      findings.push({
        rule: "SIMULATED_SECRET_EXFIL",
        description: `Simulated ${envName} was found in output. Code exfiltrated the honeytoken environment variable.`,
        severity: "critical",
        file: relativePath,
        confidence: 0.95,
        category: "malware",
        recommendation: "Confirmed credential exfiltration attempt via honeytoken detection.",
      });
    }
  }

  return findings;
}

/**
 * Get the honeytoken environment variables for sandbox injection.
 */
export function getHoneytokenEnv(): Record<string, string> {
  return { ...HONEYTOKEN_ENV };
}

/**
 * Get honeytoken file contents for sandbox filesystem.
 */
export function getHoneytokenFiles(): Array<{ path: string; content: string }> {
  return HONEYTOKEN_PATHS.map((h) => ({ path: h.path, content: h.marker }));
}
