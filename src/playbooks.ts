/**
 * Incident response playbooks (v4.6).
 *
 * Maps correlated incidents to structured response playbooks
 * with immediate actions, investigation steps, and prevention.
 */

import type { IncidentCluster, Playbook } from "./types.js";

// ---------------------------------------------------------------------------
// Playbook definitions
// ---------------------------------------------------------------------------

const PLAYBOOK_MAP: Record<string, Omit<Playbook, "incidentType" | "severity">> = {
  "GlassWorm Campaign": {
    summary: "GlassWorm supply-chain malware detected. Uses Solana blockchain for C2 communication.",
    immediateActions: [
      "Quarantine the affected package/repository immediately",
      "Block the Solana wallet addresses in network monitoring",
      "Disable any postinstall scripts in the project",
    ],
    investigationSteps: [
      "Check for the lzcdrtfxyqiplpd marker variable in all dependencies",
      "Review Solana RPC references for C2 communication patterns",
      "Examine eval/atob patterns for hidden payloads",
      "Check if environment variables were exfiltrated",
    ],
    remediationSteps: [
      "Remove the compromised package from package.json and lockfile",
      "Regenerate lockfile with npm ci after removal",
      "Rotate all secrets that were accessible to the project",
      "Update all dependencies to latest verified versions",
    ],
    preventionMeasures: [
      "Enable --ignore-scripts in CI pipelines",
      "Use supply-chain-guard in CI with --fail-on critical",
      "Pin all dependencies to exact versions",
      "Monitor Solana wallets via supply-chain-guard watchlist",
    ],
  },

  "Claude Code Leak Campaign (Vidar/GhostSocks)": {
    summary: "Fake Claude Code repository distributing Vidar stealer and GhostSocks proxy malware via GitHub releases.",
    immediateActions: [
      "Do NOT execute any downloaded files from this repository",
      "Delete any .exe or .7z files downloaded from the releases",
      "If executed: disconnect the machine from the network",
      "Report the repository to GitHub: github.com/contact/report-abuse",
    ],
    investigationSteps: [
      "Check browser data (cookies, passwords, history) for theft indicators",
      "Review cryptocurrency wallet files for unauthorized access",
      "Check for GhostSocks SOCKS5 proxy activity on the network",
      "Verify Steam/Telegram dead-drop resolver connections in network logs",
    ],
    remediationSteps: [
      "If malware was executed: reimage the affected machine",
      "Rotate ALL credentials accessible from the machine",
      "Revoke and regenerate all API tokens and SSH keys",
      "Change passwords for all accounts used on the machine",
    ],
    preventionMeasures: [
      "Never download executables from unverified GitHub repositories",
      "Verify repository legitimacy before cloning (check account age, stars pattern)",
      "Use supply-chain-guard repo <url> to analyze GitHub repos before use",
      "Be skeptical of repositories promising leaked/cracked commercial software",
    ],
  },

  "npm Account Takeover": {
    summary: "npm package maintainer account appears compromised. New maintainer added install scripts with C2 communication.",
    immediateActions: [
      "Pin the package to the last known safe version immediately",
      "Add --ignore-scripts to all npm install commands",
      "Notify the original maintainer if possible",
      "Report to npm security team",
    ],
    investigationSteps: [
      "Compare the previous version tarball with the current one",
      "Review when the maintainer change occurred",
      "Check if install scripts were added/modified in the new version",
      "Look for environment variable exfiltration patterns",
    ],
    remediationSteps: [
      "Downgrade to the last version published by the original maintainer",
      "Regenerate lockfile after downgrade",
      "Rotate npm tokens if they were accessible to the project",
      "Audit all CI/CD secrets that ran npm install with the compromised version",
    ],
    preventionMeasures: [
      "Use supply-chain-guard with known-bad version blocklist",
      "Enable npm audit in CI pipelines",
      "Monitor package maintainer changes with supply-chain-guard publishing anomaly detector",
      "Consider using npm provenance verification",
    ],
  },

  "Fake Repository Malware Distribution": {
    summary: "Repository uses social engineering (crack/leaked/unlock language) to distribute malware via GitHub releases.",
    immediateActions: [
      "Do not download or execute any files from this repository",
      "Report the repository to GitHub",
      "Warn team members who may have accessed the repository",
    ],
    investigationSteps: [
      "Check the repository owner's account age and activity",
      "Verify if star count is inflated (bot farming)",
      "Examine release artifacts for executables or archives",
      "Check if README language is designed to create urgency",
    ],
    remediationSteps: [
      "Remove any files downloaded from the repository",
      "If files were executed: treat machine as compromised",
      "Scan affected machines for malware indicators",
    ],
    preventionMeasures: [
      "Always verify repository legitimacy before use",
      "Be suspicious of repositories with piracy/crack language",
      "Use supply-chain-guard repo command to analyze unknown repos",
    ],
  },

  "CI/CD Pipeline Poisoning": {
    summary: "GitHub Actions workflow contains patterns that download/execute remote code and access secrets.",
    immediateActions: [
      "Review and disable the suspicious workflow immediately",
      "Rotate all secrets referenced in the workflow",
      "Check workflow run history for unauthorized executions",
    ],
    investigationSteps: [
      "Review the workflow for curl|bash patterns and secret references",
      "Check if secrets were sent to external URLs",
      "Examine the action sources for unpinned references",
      "Review recent workflow run logs for exfiltration",
    ],
    remediationSteps: [
      "Pin all GitHub Actions to commit SHAs",
      "Remove curl|bash patterns and replace with verified scripts",
      "Restrict secret access to only necessary workflows",
      "Enable required reviews for workflow changes",
    ],
    preventionMeasures: [
      "Use supply-chain-guard with GitHub Actions scanning in CI",
      "Require PR review for all .github/workflows changes via CODEOWNERS",
      "Use OpenID Connect instead of long-lived secrets where possible",
    ],
  },

  "Infostealer Infection (Vidar/Lumma/RedLine)": {
    summary: "Multiple infostealer indicators detected: dead-drop resolvers, browser credential theft, and crypto wallet targeting.",
    immediateActions: [
      "Disconnect affected machine from the network",
      "Do not enter any credentials on the affected machine",
      "Preserve forensic evidence before remediation",
    ],
    investigationSteps: [
      "Check for Steam/Telegram/Pastebin dead-drop resolver connections",
      "Review browser data directories for unauthorized access",
      "Check cryptocurrency wallet files for theft indicators",
      "Review temp directories for dropped executables",
    ],
    remediationSteps: [
      "Reimage the affected machine",
      "Rotate ALL credentials (passwords, tokens, keys)",
      "Revoke cryptocurrency wallet access if exposed",
      "Review financial accounts for unauthorized transactions",
    ],
    preventionMeasures: [
      "Keep software updated and use endpoint protection",
      "Scan downloaded packages with supply-chain-guard before installation",
      "Use hardware security keys for critical accounts",
    ],
  },
};

// ---------------------------------------------------------------------------
// Generate playbooks from incidents
// ---------------------------------------------------------------------------

/**
 * Generate response playbooks for detected incidents.
 */
export function generatePlaybooks(incidents: IncidentCluster[]): Playbook[] {
  const playbooks: Playbook[] = [];

  for (const incident of incidents) {
    const template = PLAYBOOK_MAP[incident.name];
    if (!template) continue;

    playbooks.push({
      incidentType: incident.name,
      severity: incident.severity,
      ...template,
    });
  }

  return playbooks;
}
