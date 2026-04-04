/**
 * Automated remediation engine (v4.6).
 *
 * Generates concrete, prioritized remediation steps for findings.
 * Maps rules to actionable fix suggestions and risk reduction scores.
 */

import type { Finding, Remediation, FixSuggestion } from "./types.js";

// ---------------------------------------------------------------------------
// Rule-to-remediation mapping
// ---------------------------------------------------------------------------

const REMEDIATION_MAP: Record<string, (f: Finding) => Remediation> = {
  INSTALL_HOOK_NETWORK: (f) => ({
    id: `rem-${f.rule}`,
    title: "Disable install scripts in CI",
    description: "Install scripts make network calls during npm install.",
    priority: "critical",
    category: "dependency",
    steps: [
      "Run `npm ci --ignore-scripts` in CI pipelines",
      "Review the package's install scripts manually",
      "Consider replacing the package with a safer alternative",
    ],
    automated: false,
    riskReduction: 30,
  }),
  INSTALL_HOOK_DOWNLOAD_EXEC: (f) => ({
    id: `rem-${f.rule}`,
    title: "Block download-and-execute install scripts",
    description: "Install script downloads and executes remote code.",
    priority: "critical",
    category: "dependency",
    steps: [
      "Immediately add `--ignore-scripts` to npm install commands",
      "Pin the package to the last known safe version",
      "Report to npm security: npm.community",
      "Consider removing the package entirely",
    ],
    automated: false,
    riskReduction: 40,
  }),
  GHA_UNPINNED_ACTION: (f) => ({
    id: `rem-${f.rule}`,
    title: "Pin GitHub Action to commit SHA",
    description: "Unpinned actions can be replaced with malicious code.",
    priority: "high",
    category: "ci",
    steps: [
      "Find the current commit SHA for the action version",
      "Replace `@main`/`@v1` with `@<full-sha>`",
      "Add a comment with the original version tag for reference",
    ],
    automated: true,
    riskReduction: 20,
  }),
  IOC_KNOWN_BAD_VERSION: (f) => ({
    id: `rem-${f.rule}`,
    title: "Remove compromised package version",
    description: "A known-compromised package version is installed.",
    priority: "critical",
    category: "dependency",
    steps: [
      "Remove the package from node_modules: `rm -rf node_modules/<pkg>`",
      "Update to the latest safe version in package.json",
      "Regenerate lockfile: `rm package-lock.json && npm install`",
      "Audit CI/CD secrets that may have been exposed",
    ],
    automated: false,
    riskReduction: 50,
  }),
  TYPOSQUAT_LEVENSHTEIN: (f) => ({
    id: `rem-${f.rule}`,
    title: "Verify dependency name is correct",
    description: "Package name is very similar to a popular package.",
    priority: "high",
    category: "dependency",
    steps: [
      "Check if the dependency name is correct (compare with intended package)",
      "Remove the typosquatted package if confirmed wrong",
      "Install the correct package",
    ],
    automated: false,
    riskReduction: 25,
  }),
  CONFIG_HTTP_REGISTRY: () => ({
    id: "rem-CONFIG_HTTP_REGISTRY",
    title: "Switch to HTTPS registry",
    description: "Package manager uses HTTP registry (MITM risk).",
    priority: "critical",
    category: "policy",
    steps: [
      "Change `registry=http://...` to `registry=https://...` in .npmrc",
      "Verify the registry supports HTTPS",
    ],
    automated: true,
    riskReduction: 25,
  }),
  CONFIG_AUTH_TOKEN_EXPOSED: () => ({
    id: "rem-CONFIG_AUTH_TOKEN_EXPOSED",
    title: "Remove exposed auth token",
    description: "Auth token committed to version control.",
    priority: "critical",
    category: "secret",
    steps: [
      "Remove the token from the config file",
      "Revoke the exposed token immediately",
      "Generate a new token and store it in a secret manager or environment variable",
      "Add the config file to .gitignore if appropriate",
    ],
    automated: false,
    riskReduction: 40,
  }),
  SECRETS_AWS_KEY: () => ({
    id: "rem-SECRETS_AWS_KEY",
    title: "Rotate exposed AWS credentials",
    description: "AWS access key detected in source code.",
    priority: "critical",
    category: "secret",
    steps: [
      "Deactivate the exposed key in AWS IAM immediately",
      "Generate new access keys",
      "Store credentials in environment variables or AWS Secrets Manager",
      "Review CloudTrail logs for unauthorized usage",
    ],
    automated: false,
    riskReduction: 50,
  }),
  SECRETS_GITHUB_TOKEN: () => ({
    id: "rem-SECRETS_GITHUB_TOKEN",
    title: "Revoke exposed GitHub token",
    description: "GitHub personal access token detected in code.",
    priority: "critical",
    category: "secret",
    steps: [
      "Revoke the token at github.com/settings/tokens",
      "Generate a new token with minimal required scopes",
      "Store in environment variable or secret manager",
      "Review GitHub audit log for unauthorized actions",
    ],
    automated: false,
    riskReduction: 45,
  }),
  DOCKER_CURL_PIPE: () => ({
    id: "rem-DOCKER_CURL_PIPE",
    title: "Replace curl|bash with verified download",
    description: "Dockerfile pipes remote content to shell.",
    priority: "critical",
    category: "ci",
    steps: [
      "Download the script to a file first",
      "Verify checksum before executing",
      "Pin the download URL to a specific version",
    ],
    automated: true,
    riskReduction: 20,
  }),
};

// ---------------------------------------------------------------------------
// Generate remediations
// ---------------------------------------------------------------------------

/**
 * Generate remediation plan from findings.
 */
export function generateRemediations(findings: Finding[]): Remediation[] {
  const remediations: Remediation[] = [];
  const seen = new Set<string>();

  for (const finding of findings) {
    const generator = REMEDIATION_MAP[finding.rule];
    if (!generator) continue;

    const key = finding.rule;
    if (seen.has(key)) continue;
    seen.add(key);

    remediations.push(generator(finding));
  }

  // Sort by priority
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  remediations.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  return remediations;
}

/**
 * Generate fix suggestions for automatable remediations.
 */
export function generateFixSuggestions(findings: Finding[]): FixSuggestion[] {
  const fixes: FixSuggestion[] = [];

  for (const f of findings) {
    if (f.rule === "GHA_UNPINNED_ACTION" && f.match) {
      const match = f.match.match(/uses:\s*([^@]+)@(\S+)/);
      if (match) {
        fixes.push({
          targetFile: f.file ?? ".github/workflows/*.yml",
          changeType: "replace",
          before: `uses: ${match[1]}@${match[2]}`,
          after: `uses: ${match[1]}@<commit-sha> # ${match[2]}`,
          explanation: "Pin action to commit SHA to prevent supply-chain attacks via mutable tags.",
        });
      }
    }

    if (f.rule === "CONFIG_HTTP_REGISTRY" && f.match) {
      fixes.push({
        targetFile: f.file ?? ".npmrc",
        changeType: "replace",
        before: f.match,
        after: f.match.replace("http://", "https://"),
        explanation: "Switch from HTTP to HTTPS to prevent man-in-the-middle attacks.",
      });
    }
  }

  return fixes;
}
