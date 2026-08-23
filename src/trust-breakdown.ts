/**
 * Trust breakdown calculator (v4.2).
 *
 * Computes a multi-dimensional trust score for npm/pypi packages:
 * Publisher Trust, Code Quality, Dependency Trust, Release Process.
 */

import type { Finding, TrustBreakdown, TrustDimension, TrustIndicator } from "./types.js";

/**
 * Calculate trust breakdown from findings and package metadata.
 *
 * Mode-aware (Issue #202):
 * - When scanning a remote package or repository (`github`, `npm`, `pypi`), all 4
 *   dimensions (Publisher, Code, Dependencies, Release) are assessed.
 * - When scanning a local directory (`directory`), Publisher Trust and Release Process
 *   are marked as `assessed: false` unless relevant anomaly signals were detected,
 *   and the overall score is renormalised across the assessed dimensions rather
 *   than falsely reporting unexamined dimensions as 100/100.
 */
export function calculateTrustBreakdown(
  findings: Finding[],
  packageName: string,
  hasLockfile: boolean,
  scanType: string = "package",
): TrustBreakdown {
  const isRemoteOrPkg =
    scanType === "github" ||
    scanType === "npm" ||
    scanType === "pypi" ||
    scanType === "package";
  const publisherFindings = findings.filter(
    (f) =>
      f.rule === "PUBLISH_MAINTAINER_CHANGE" ||
      f.rule === "REPO_NEW_ACCOUNT" ||
      f.rule === "REPO_KNOWN_MALICIOUS_ACCOUNT" ||
      f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT" ||
      f.rule === "PUBLISH_VERSION_GAP",
  );
  const releaseFindings = findings.filter(
    (f) => f.rule.startsWith("RELEASE_") || f.rule === "PUBLISH_SCRIPT_ADDED",
  );

  const publisherAssessed = isRemoteOrPkg || publisherFindings.length > 0;
  const releaseAssessed = isRemoteOrPkg || releaseFindings.length > 0;

  const publisherTrust: TrustDimension = publisherAssessed
    ? calcPublisherTrust(findings)
    : {
        score: 0,
        indicators: [
          {
            name: "Publisher signals",
            status: "yellow",
            detail: "Not assessed for local directory scan",
          },
        ],
        assessed: false,
      };

  const codeQuality: TrustDimension = calcCodeQuality(findings);
  const dependencyTrust: TrustDimension = calcDependencyTrust(findings, hasLockfile);

  const releaseProcess: TrustDimension = releaseAssessed
    ? calcReleaseProcess(findings)
    : {
        score: 0,
        indicators: [
          {
            name: "Release signals",
            status: "yellow",
            detail: "Not assessed for local directory scan",
          },
        ],
        assessed: false,
      };

  let weightedSum = 0;
  let totalWeight = 0;

  if (publisherTrust.assessed !== false) {
    weightedSum += publisherTrust.score * 0.4;
    totalWeight += 0.4;
  }
  if (codeQuality.assessed !== false) {
    weightedSum += codeQuality.score * 0.3;
    totalWeight += 0.3;
  }
  if (dependencyTrust.assessed !== false) {
    weightedSum += dependencyTrust.score * 0.2;
    totalWeight += 0.2;
  }
  if (releaseProcess.assessed !== false) {
    weightedSum += releaseProcess.score * 0.1;
    totalWeight += 0.1;
  }

  const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 100;

  return {
    publisherTrust,
    codeQuality,
    dependencyTrust,
    releaseProcess,
    overallScore,
  };
}

function calcPublisherTrust(findings: Finding[]): TrustDimension {
  const indicators: TrustIndicator[] = [];
  let score = 100;

  // Check for maintainer change
  if (findings.some((f) => f.rule === "PUBLISH_MAINTAINER_CHANGE")) {
    score -= 40;
    indicators.push({ name: "Maintainer change", status: "red", detail: "Maintainer changed before recent release" });
  } else {
    indicators.push({ name: "Maintainer stable", status: "green", detail: "No recent maintainer changes" });
  }

  // Check for new account
  if (findings.some((f) => f.rule === "REPO_NEW_ACCOUNT")) {
    score -= 30;
    indicators.push({ name: "Account age", status: "red", detail: "Publisher account < 90 days old" });
  } else {
    indicators.push({ name: "Account age", status: "green", detail: "Established publisher account" });
  }

  // Check for known malicious account
  if (findings.some((f) => f.rule === "REPO_KNOWN_MALICIOUS_ACCOUNT" || f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT")) {
    score = 0;
    indicators.push({ name: "Known malicious", status: "red", detail: "Publisher is a known malicious account" });
  }

  // Version gap
  if (findings.some((f) => f.rule === "PUBLISH_VERSION_GAP")) {
    score -= 15;
    indicators.push({ name: "Version gap", status: "yellow", detail: "Long gap between releases" });
  }

  return { score: Math.max(0, score), indicators, assessed: true };
}

function calcCodeQuality(findings: Finding[]): TrustDimension {
  const indicators: TrustIndicator[] = [];
  let score = 100;

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  if (critical > 0) {
    score -= Math.min(60, critical * 20);
    indicators.push({ name: "Critical findings", status: "red", detail: `${critical} critical issue(s) found` });
  } else {
    indicators.push({ name: "No critical findings", status: "green", detail: "Zero critical issues" });
  }

  if (high > 0) {
    score -= Math.min(30, high * 10);
    indicators.push({ name: "High findings", status: high > 3 ? "red" : "yellow", detail: `${high} high-severity issue(s)` });
  } else {
    indicators.push({ name: "No high findings", status: "green", detail: "Zero high-severity issues" });
  }

  // Obfuscation check
  const hasObfuscation = findings.some((f) =>
    f.rule.includes("EVAL_") || f.rule.includes("OBFUSCATION") || f.rule === "HIGH_ENTROPY_STRING",
  );
  if (hasObfuscation) {
    score -= 20;
    indicators.push({ name: "Obfuscation", status: "red", detail: "Obfuscated code detected" });
  } else {
    indicators.push({ name: "Code clarity", status: "green", detail: "No obfuscation detected" });
  }

  return { score: Math.max(0, score), indicators, assessed: true };
}

function calcDependencyTrust(findings: Finding[], hasLockfile: boolean): TrustDimension {
  const indicators: TrustIndicator[] = [];
  let score = 100;

  // Known bad versions
  if (findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")) {
    score -= 50;
    indicators.push({ name: "Bad versions", status: "red", detail: "Known compromised package version detected" });
  } else {
    indicators.push({ name: "Clean versions", status: "green", detail: "No known-bad versions" });
  }

  // Lockfile integrity
  const lockIssues = findings.filter((f) => f.rule.startsWith("LOCKFILE_"));
  if (lockIssues.length > 0) {
    score -= Math.min(30, lockIssues.length * 10);
    indicators.push({ name: "Lockfile issues", status: "yellow", detail: `${lockIssues.length} lockfile integrity issue(s)` });
  } else if (hasLockfile) {
    indicators.push({ name: "Lockfile integrity", status: "green", detail: "Lockfile is clean" });
  }

  // Typosquatting
  if (findings.some((f) => f.rule.startsWith("TYPOSQUAT_"))) {
    score -= 30;
    indicators.push({ name: "Typosquatting", status: "red", detail: "Possible typosquatted dependency" });
  }

  return { score: Math.max(0, score), indicators, assessed: true };
}

function calcReleaseProcess(findings: Finding[]): TrustDimension {
  const indicators: TrustIndicator[] = [];
  let score = 100;

  // Suspicious release artifacts
  const releaseIssues = findings.filter((f) => f.rule.startsWith("RELEASE_"));
  if (releaseIssues.length > 0) {
    score -= Math.min(50, releaseIssues.length * 15);
    indicators.push({ name: "Release artifacts", status: "red", detail: `${releaseIssues.length} suspicious release artifact(s)` });
  } else {
    indicators.push({ name: "Release artifacts", status: "green", detail: "Clean release artifacts" });
  }

  // Install script additions
  if (findings.some((f) => f.rule === "PUBLISH_SCRIPT_ADDED")) {
    score -= 25;
    indicators.push({ name: "Script change", status: "yellow", detail: "Install scripts added in recent version" });
  }

  return { score: Math.max(0, score), indicators, assessed: true };
}
