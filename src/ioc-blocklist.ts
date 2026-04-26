/**
 * Known Indicators of Compromise (IOC) blocklist.
 *
 * Contains known malicious domains, IPs, hashes, GitHub accounts,
 * and compromised package versions. Updated as new threats emerge.
 */

// ---------------------------------------------------------------------------
// Known malicious C2 domains
// ---------------------------------------------------------------------------

export const KNOWN_C2_DOMAINS: string[] = [
  // Vidar stealer C2 (Claude Code leak campaign, April 2026)
  "rti.cargomanbd.com",

  // GlassWorm C2 domains
  "connect.*.workers.dev",

  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  "audit.checkmarx.cx",
  "checkmarx.cx",
];

// ---------------------------------------------------------------------------
// Known malicious C2 IPs
// ---------------------------------------------------------------------------

export const KNOWN_C2_IPS: string[] = [
  // GhostSocks C2 (Claude Code leak campaign, April 2026)
  "147.45.197.92",
  "94.228.161.88",

  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  "94.154.172.43",
  "91.195.240.123",
];

// ---------------------------------------------------------------------------
// Known dead-drop resolver URLs
// ---------------------------------------------------------------------------

export const KNOWN_DEAD_DROPS: string[] = [
  // Vidar dead-drop resolvers (Claude Code leak campaign)
  "steamcommunity.com/profiles/76561198721263282",
  "telegram.me/g1n3sss",
  "t.me/g1n3sss",
];

// ---------------------------------------------------------------------------
// Known malicious file hashes (MD5)
// ---------------------------------------------------------------------------

export const KNOWN_MALICIOUS_HASHES: Record<string, string> = {
  // Claude Code leak campaign (April 2026)
  "d8256fbc62e85dae85eb8d4b49613774": "Claude Code malware archive",
  "8660646bbc6bb7dc8f59a764e25fe1fd": "Claude Code malware archive (variant)",
  "77c73bd5e7625b7f691bc00a1b561a0f": "ClaudeCode_x64.exe Rust dropper",
  "81fb210ba148fd39e999ee9cdc085dfc": "ClaudeCode_x64.exe Rust dropper (variant)",
  "9a6ea91491ccb1068b0592402029527f": "Vidar v18.7 stealer",
  "3388b415610f4ae018d124ea4dc99189": "GhostSocks proxy malware",
};

// ---------------------------------------------------------------------------
// Known malicious GitHub accounts
// ---------------------------------------------------------------------------

export const KNOWN_MALICIOUS_GITHUB_ACCOUNTS: string[] = [
  "idbzoomh",
  "idbzoomh1",
  "my3jie",
];

// ---------------------------------------------------------------------------
// Known compromised npm package versions
// ---------------------------------------------------------------------------

export const KNOWN_BAD_NPM_VERSIONS: Record<string, { versions: string[]; description: string }> = {
  "ua-parser-js": {
    versions: ["0.7.29", "0.8.0", "1.0.0"],
    description: "ua-parser-js hijack: crypto miner + credential stealer (Oct 2021)",
  },
  "coa": {
    versions: ["2.0.3", "2.0.4"],
    description: "coa npm hijack: sdd.dll trojan payload (Nov 2021)",
  },
  "rc": {
    versions: ["1.2.9", "1.3.9", "2.3.9"],
    description: "rc npm hijack: sdd.dll trojan payload (Nov 2021)",
  },
  "event-stream": {
    versions: ["3.3.6"],
    description: "event-stream: flatmap-stream backdoor targeting copay wallet (Nov 2018)",
  },
  "axios": {
    versions: ["1.14.1", "0.30.4"],
    description: "axios hijack: embedded RAT (plain-crypto-js) (March 2026)",
  },
  "colors": {
    versions: ["1.4.1", "1.4.2"],
    description: "colors.js protestware: infinite loop (Jan 2022)",
  },
  "faker": {
    versions: ["6.6.6"],
    description: "faker.js protestware: infinite loop + data wipe (Jan 2022)",
  },
  "node-ipc": {
    versions: ["10.1.1", "10.1.2", "10.1.3"],
    description: "node-ipc protestware: overwrites files for Russian/Belarusian IPs (Mar 2022)",
  },
  "@bitwarden/cli": {
    versions: ["2026.4.0"],
    description: "Bitwarden CLI hijack: bw_setup.js/bw1.js credential stealer linked to Checkmarx KICS breach (April 2026)",
  },
};

// ---------------------------------------------------------------------------
// Known compromised PyPI package versions
// ---------------------------------------------------------------------------

export const KNOWN_BAD_PYPI_VERSIONS: Record<string, { versions: string[]; description: string }> = {
  "ctx": {
    versions: ["0.1.2", "0.2.6"],
    description: "ctx PyPI hijack: steals environment variables (May 2022)",
  },
};

// ---------------------------------------------------------------------------
// Utility: check if a string contains any known IOC
// ---------------------------------------------------------------------------

import type { Finding } from "./types.js";

/**
 * Check content against known IOC blocklists.
 */
export function checkIOCBlocklist(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const contentLower = content.toLowerCase();

  // Check known C2 domains
  for (const domain of KNOWN_C2_DOMAINS) {
    const domainPattern = domain.replace(/\./g, "\\.").replace(/\*/g, "\\w+");
    const regex = new RegExp(domainPattern, "i");
    if (regex.test(content)) {
      findings.push({
        rule: "IOC_KNOWN_C2_DOMAIN",
        description: `Known malicious C2 domain detected: ${domain}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This domain is a known command-and-control server. Quarantine this code immediately.",
      });
    }
  }

  // Check known C2 IPs
  for (const ip of KNOWN_C2_IPS) {
    if (content.includes(ip)) {
      findings.push({
        rule: "IOC_KNOWN_C2_IP",
        description: `Known malicious C2 IP address detected: ${ip}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This IP is a known command-and-control server. Quarantine this code immediately.",
      });
    }
  }

  // Check known dead-drop resolvers
  for (const url of KNOWN_DEAD_DROPS) {
    if (contentLower.includes(url.toLowerCase())) {
      findings.push({
        rule: "IOC_KNOWN_DEAD_DROP",
        description: `Known dead-drop resolver URL detected: ${url}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This URL is used as a dead-drop resolver to retrieve C2 addresses. This is a strong malware indicator.",
      });
    }
  }

  // Check known malicious hashes
  for (const [hash, desc] of Object.entries(KNOWN_MALICIOUS_HASHES)) {
    if (contentLower.includes(hash.toLowerCase())) {
      findings.push({
        rule: "IOC_KNOWN_MALWARE_HASH",
        description: `Known malware hash detected: ${hash} (${desc})`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This hash matches known malware. Do not execute any associated files.",
      });
    }
  }

  // Check known malicious GitHub accounts
  for (const account of KNOWN_MALICIOUS_GITHUB_ACCOUNTS) {
    const pattern = new RegExp(`github\\.com/${account}\\b`, "i");
    if (pattern.test(content)) {
      findings.push({
        rule: "IOC_KNOWN_MALICIOUS_ACCOUNT",
        description: `Reference to known malicious GitHub account: ${account}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This GitHub account is known to distribute malware. Do not clone or use code from this source.",
      });
    }
  }

  return findings;
}

/**
 * Check a package name + version against the known-bad blocklist.
 */
export function checkBadVersion(
  name: string,
  version: string,
  ecosystem: "npm" | "pypi",
): Finding | null {
  const blocklist =
    ecosystem === "npm" ? KNOWN_BAD_NPM_VERSIONS : KNOWN_BAD_PYPI_VERSIONS;

  const entry = blocklist[name];
  if (!entry) return null;

  if (entry.versions.includes(version)) {
    return {
      rule: "IOC_KNOWN_BAD_VERSION",
      description: `Known compromised package version: ${name}@${version} — ${entry.description}`,
      severity: "critical",
      recommendation: `Remove ${name}@${version} immediately. This version contains known malware. Upgrade to a clean version.`,
    };
  }

  return null;
}
