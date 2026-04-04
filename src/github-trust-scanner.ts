/**
 * GitHub repository trust signal scanner.
 *
 * Analyzes GitHub repo metadata for indicators of fake/malicious repos:
 * star-farming, new accounts, suspicious releases, lure READMEs, etc.
 * Uses `gh` CLI for API access (no token configuration needed).
 */

import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { LURE_PATTERNS } from "./patterns.js";
import { KNOWN_MALICIOUS_GITHUB_ACCOUNTS } from "./ioc-blocklist.js";

interface RepoMetadata {
  owner: string;
  name: string;
  stars: number;
  forks: number;
  openIssues: number;
  hasIssues: boolean;
  createdAt: string;
  pushedAt: string;
  isOrg: boolean;
  ownerCreatedAt?: string;
  defaultBranch: string;
  commitCount?: number;
  contributorCount?: number;
}

interface ReleaseAsset {
  name: string;
  size: number;
  downloadCount: number;
}

interface Release {
  tagName: string;
  name: string;
  createdAt: string;
  assets: ReleaseAsset[];
}

/**
 * Check if `gh` CLI is available.
 */
function hasGhCli(): boolean {
  try {
    execSync("gh --version", { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Fetch repo metadata via `gh api`.
 */
function fetchRepoMetadata(owner: string, repo: string): RepoMetadata | null {
  try {
    const json = execSync(
      `gh api repos/${owner}/${repo} --jq '{stars: .stargazers_count, forks: .forks_count, openIssues: .open_issues_count, hasIssues: .has_issues, createdAt: .created_at, pushedAt: .pushed_at, isOrg: (.owner.type == "Organization"), ownerLogin: .owner.login, defaultBranch: .default_branch}'`,
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    const data = JSON.parse(json);

    // Fetch owner account age
    let ownerCreatedAt: string | undefined;
    try {
      const ownerJson = execSync(
        `gh api users/${owner} --jq '.created_at'`,
        { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
      );
      ownerCreatedAt = ownerJson.trim();
    } catch { /* skip */ }

    // Fetch commit count
    let commitCount: number | undefined;
    try {
      const commitJson = execSync(
        `gh api repos/${owner}/${repo}/commits?per_page=1 --jq 'length'`,
        { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
      );
      commitCount = parseInt(commitJson.trim(), 10);
    } catch { /* skip */ }

    // Fetch contributor count
    let contributorCount: number | undefined;
    try {
      const contribJson = execSync(
        `gh api repos/${owner}/${repo}/contributors?per_page=5 --jq 'length'`,
        { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
      );
      contributorCount = parseInt(contribJson.trim(), 10);
    } catch { /* skip */ }

    return {
      owner,
      name: repo,
      stars: data.stars ?? 0,
      forks: data.forks ?? 0,
      openIssues: data.openIssues ?? 0,
      hasIssues: data.hasIssues ?? true,
      createdAt: data.createdAt ?? "",
      pushedAt: data.pushedAt ?? "",
      isOrg: data.isOrg ?? false,
      ownerCreatedAt,
      defaultBranch: data.defaultBranch ?? "main",
      commitCount,
      contributorCount,
    };
  } catch {
    return null;
  }
}

/**
 * Fetch release info via `gh api`.
 */
function fetchReleases(owner: string, repo: string): Release[] {
  try {
    const json = execSync(
      `gh api repos/${owner}/${repo}/releases?per_page=5 --jq '[.[] | {tagName: .tag_name, name: .name, createdAt: .created_at, assets: [.assets[] | {name: .name, size: .size, downloadCount: .download_count}]}]'`,
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    return JSON.parse(json) as Release[];
  } catch {
    return [];
  }
}

/**
 * Parse a GitHub URL into owner/repo.
 */
export function parseGitHubUrl(
  url: string,
): { owner: string; repo: string } | null {
  const match = url.match(
    /github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/,
  );
  if (!match) return null;
  return { owner: match[1], repo: match[2].replace(/\.git$/, "") };
}

/**
 * Analyze a GitHub repo for trust signals.
 */
export function analyzeGitHubTrust(
  owner: string,
  repo: string,
): Finding[] {
  if (!hasGhCli()) return [];

  const findings: Finding[] = [];

  // Check known malicious accounts
  if (KNOWN_MALICIOUS_GITHUB_ACCOUNTS.includes(owner.toLowerCase())) {
    findings.push({
      rule: "REPO_KNOWN_MALICIOUS_ACCOUNT",
      description: `Repository owner "${owner}" is a known malicious GitHub account.`,
      severity: "critical",
      recommendation:
        "Do not use code from this repository. This account has been identified as distributing malware.",
    });
    return findings; // No need to check further
  }

  // Fetch metadata
  const meta = fetchRepoMetadata(owner, repo);
  if (!meta) return findings;

  const now = Date.now();
  const repoAge = now - new Date(meta.createdAt).getTime();
  const daysSinceCreation = repoAge / (1000 * 60 * 60 * 24);

  // Account age check
  if (meta.ownerCreatedAt) {
    const accountAge =
      now - new Date(meta.ownerCreatedAt).getTime();
    const accountDays = accountAge / (1000 * 60 * 60 * 24);
    if (accountDays < 90) {
      findings.push({
        rule: "REPO_NEW_ACCOUNT",
        description: `Repository owner account is ${Math.round(accountDays)} days old (< 90 days). New accounts are higher risk.`,
        severity: "high",
        recommendation:
          "Exercise caution with code from newly created accounts. Verify the maintainer's identity.",
      });
    }
  }

  // Repo recently created with many stars
  if (daysSinceCreation < 30 && meta.stars > 50) {
    findings.push({
      rule: "REPO_RECENT_CREATION",
      description: `Repository is ${Math.round(daysSinceCreation)} days old with ${meta.stars} stars. Rapid star growth on a new repo is a star-farming indicator.`,
      severity: "high",
      recommendation:
        "Star-farming bots inflate stars on malicious repos. Verify the repo's legitimacy through code review.",
    });
  }

  // Star/fork ratio check (forks > stars is unusual for organic repos)
  if (meta.stars > 20 && meta.forks > meta.stars * 1.5) {
    findings.push({
      rule: "REPO_STAR_FORK_RATIO",
      description: `Unusual star/fork ratio: ${meta.stars} stars vs ${meta.forks} forks. More forks than stars can indicate bot activity.`,
      severity: "high",
      recommendation:
        "Check if forks are from real, active accounts or star-farming bots.",
    });
  }

  // Few contributors on popular repo
  if (
    meta.contributorCount !== undefined &&
    meta.contributorCount < 2 &&
    meta.stars > 100
  ) {
    findings.push({
      rule: "REPO_FEW_CONTRIBUTORS",
      description: `Only ${meta.contributorCount} contributor(s) on a repo with ${meta.stars} stars. Legitimate popular projects typically have multiple contributors.`,
      severity: "medium",
      recommendation:
        "Single-contributor repos with high stars may be fake. Check contributor history.",
    });
  }

  // No issues on popular repo
  if (!meta.hasIssues || (meta.openIssues === 0 && meta.stars > 50)) {
    findings.push({
      rule: "REPO_NO_ISSUES",
      description: `Issues ${meta.hasIssues ? "have 0 open items" : "are disabled"} on a repo with ${meta.stars} stars. Malicious repos often disable issues to avoid reports.`,
      severity: "medium",
      recommendation:
        "Legitimate projects encourage issue reporting. Disabled issues is a red flag.",
    });
  }

  // Single commit repos
  if (meta.commitCount !== undefined && meta.commitCount <= 2 && meta.stars > 10) {
    findings.push({
      rule: "REPO_SINGLE_COMMIT",
      description: `Only ${meta.commitCount} commit(s) in a repo with ${meta.stars} stars. Malware repos are typically single-commit drops.`,
      severity: "high",
      recommendation:
        "Single-commit repos with stars are a strong malware indicator. Review the commit content.",
    });
  }

  // Check releases for suspicious artifacts
  const releases = fetchReleases(owner, repo);
  for (const release of releases) {
    // Executable artifacts
    const suspiciousExts = [".exe", ".msi", ".bat", ".cmd", ".ps1", ".scr", ".com"];
    const archiveExts = [".7z", ".rar"];

    for (const asset of release.assets) {
      const lowerName = asset.name.toLowerCase();
      const ext = path.extname(lowerName);

      if (suspiciousExts.includes(ext)) {
        findings.push({
          rule: "RELEASE_EXE_ARTIFACT",
          description: `Executable file "${asset.name}" (${formatSize(asset.size)}) in release "${release.tagName}". GitHub releases should not contain executables.`,
          severity: "critical",
          recommendation:
            "Do NOT download this file. Executables in GitHub releases are a primary malware distribution vector.",
        });
      }

      if (archiveExts.includes(ext)) {
        findings.push({
          rule: "RELEASE_7Z_ARCHIVE",
          description: `Compressed archive "${asset.name}" (${formatSize(asset.size)}) in release "${release.tagName}". .7z/.rar archives are used to evade antivirus scanning.`,
          severity: "high",
          recommendation:
            "Password-protected and compressed archives bypass AV detection. Inspect contents before extracting.",
        });
      }

      // Size anomaly (> 50MB)
      if (asset.size > 50 * 1024 * 1024) {
        findings.push({
          rule: "RELEASE_SIZE_ANOMALY",
          description: `Large release artifact "${asset.name}" (${formatSize(asset.size)}). Unusually large files may contain bundled malware.`,
          severity: "high",
          recommendation:
            "Verify this file size is expected for the project.",
        });
      }
    }

    // Lure release names
    const lowerReleaseName = (release.name || release.tagName).toLowerCase();
    const lureKeywords = ["leaked", "cracked", "free", "unlocked", "keygen", "bypass", "premium", "enterprise"];
    for (const keyword of lureKeywords) {
      if (lowerReleaseName.includes(keyword)) {
        findings.push({
          rule: "RELEASE_NAME_LURE",
          description: `Release "${release.name || release.tagName}" contains lure keyword "${keyword}". This is a social engineering tactic for malware distribution.`,
          severity: "high",
          recommendation:
            "Releases with piracy/crack language are almost always malware. Do not download.",
        });
        break;
      }
    }
  }

  return findings;
}

/**
 * Scan README content for lure patterns.
 */
export function scanReadmeLures(
  readmeContent: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const lines = readmeContent.split("\n");

  for (const pattern of LURE_PATTERNS) {
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
          recommendation: getLureRecommendation(pattern.rule),
        });
        break; // One match per pattern per file
      }
    }
  }

  return findings;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getLureRecommendation(rule: string): string {
  const map: Record<string, string> = {
    README_LURE_LEAKED:
      "This README uses 'leaked' language to lure downloads. Verify the project's legitimacy before using.",
    README_LURE_CRACK:
      "This README promises cracked/unlocked software. This is almost certainly malware. Do NOT download.",
    README_LURE_URGENCY:
      "Urgency language in README is a social engineering tactic. Legitimate projects don't pressure downloads.",
    CAMPAIGN_CLAUDE_LURE:
      "CRITICAL: This matches the April 2026 Claude Code malware campaign (Vidar/GhostSocks). Quarantine immediately.",
    CAMPAIGN_AI_TOOL_LURE:
      "CRITICAL: This matches the 2026 fake AI tool campaign targeting developers. Do not use this code.",
    FAKE_AI_TOOL_LURE:
      "Suspicious executable naming pattern matching malware campaigns. Verify file integrity.",
  };
  return map[rule] ?? "Review this content for social engineering tactics.";
}
