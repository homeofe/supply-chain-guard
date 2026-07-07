/**
 * Publishing anomaly detector (v4.2).
 *
 * Detects account-takeover signals and suspicious publishing patterns
 * by analyzing npm registry metadata: maintainer changes, version gaps,
 * script additions, and republish events.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as https from "node:https";
import type { Finding } from "./types.js";

interface NpmVersionMeta {
  version: string;
  publishedAt: string;
  maintainers: string[];
  hasInstallScripts: boolean;
  tarballUrl: string;
}

/**
 * Analyze npm package publishing history for anomalies.
 * Requires pre-fetched version metadata (from npm registry API).
 */
export function analyzePublishingAnomalies(
  packageName: string,
  versions: NpmVersionMeta[],
): Finding[] {
  const findings: Finding[] = [];
  if (versions.length < 2) return findings;

  // Sort by publish date
  const sorted = [...versions].sort(
    (a, b) => new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime(),
  );

  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const curr = sorted[i];

    // Maintainer change
    const prevMaintainers = new Set(prev.maintainers);
    const newMaintainers = curr.maintainers.filter((m) => !prevMaintainers.has(m));
    if (newMaintainers.length > 0) {
      findings.push({
        rule: "PUBLISH_MAINTAINER_CHANGE",
        description: `${packageName}@${curr.version}: New maintainer(s) added before release: ${newMaintainers.join(", ")}. Possible account takeover.`,
        severity: "critical",
        confidence: 0.75,
        category: "supply-chain",
        recommendation: `Verify the maintainer change on ${packageName} was intentional. Account takeovers often precede malicious releases.`,
      });
    }

    // Version gap (> 2 years)
    const gapMs = new Date(curr.publishedAt).getTime() - new Date(prev.publishedAt).getTime();
    const gapDays = gapMs / (1000 * 60 * 60 * 24);
    if (gapDays > 730) {
      findings.push({
        rule: "PUBLISH_VERSION_GAP",
        description: `${packageName}@${curr.version}: Published ${Math.round(gapDays)} days after previous version. Dormant packages suddenly publishing are a takeover indicator.`,
        severity: "high",
        confidence: 0.65,
        category: "supply-chain",
        recommendation: `A ${Math.round(gapDays / 365)}-year gap before a new release is unusual. Check if the maintainer account was compromised.`,
      });
    }

    // Install scripts added (didn't have them before)
    if (!prev.hasInstallScripts && curr.hasInstallScripts) {
      findings.push({
        rule: "PUBLISH_SCRIPT_ADDED",
        description: `${packageName}@${curr.version}: Install scripts were added in this version (previous had none). New install scripts can execute malware on npm install.`,
        severity: "high",
        confidence: 0.7,
        category: "supply-chain",
        recommendation: `Review the new install scripts in ${packageName}@${curr.version}. Legitimate packages rarely add install hooks to existing releases.`,
      });
    }

    // Version number jump (e.g., 1.0.0 → 9.0.0)
    const prevMajor = parseInt(prev.version.split(".")[0], 10);
    const currMajor = parseInt(curr.version.split(".")[0], 10);
    if (!isNaN(prevMajor) && !isNaN(currMajor) && currMajor - prevMajor > 3) {
      findings.push({
        rule: "PUBLISH_VERSION_JUMP",
        description: `${packageName}@${curr.version}: Major version jumped from ${prevMajor} to ${currMajor}. Large version jumps can indicate a dependency confusion attack (higher version wins).`,
        severity: "high",
        confidence: 0.6,
        category: "supply-chain",
        recommendation: `Verify ${packageName}@${curr.version} is legitimate. Dependency confusion attacks use abnormally high version numbers.`,
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Registry version-drift (v5.9, opt-in --check-registry)
// ---------------------------------------------------------------------------
//
// Compares the LOCAL source package.json version against the npm registry
// 'latest' dist-tag. The concerning signal is "the code you are auditing is a
// major version behind what npm actually installs" - i.e. the published artifact
// may not correspond to the source in front of you. This is opt-in because it
// needs a network call, which the tool's local/offline scans otherwise avoid.

const NPM_REGISTRY_URL = "https://registry.npmjs.org";

/** Parse the numeric core of a semver string (ignores prerelease/build suffix). */
function parseSemverCore(v: string): { major: number; minor: number; patch: number } | null {
  const m = /^\s*v?(\d+)\.(\d+)\.(\d+)/.exec(v);
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

/**
 * Pure comparison: returns a finding when the LOCAL source version is a whole
 * major (or more) behind the registry 'latest'. Same-major minor/patch lag and
 * source-ahead (unreleased dev) are intentionally NOT flagged - they are common
 * and benign, and flagging them would make the check noisy.
 */
export function evaluateVersionDrift(
  packageName: string,
  localVersion: string,
  registryLatest: string,
): Finding | null {
  const local = parseSemverCore(localVersion);
  const reg = parseSemverCore(registryLatest);
  if (!local || !reg) return null;

  if (reg.major > local.major) {
    const gap = reg.major - local.major;
    return {
      rule: "REGISTRY_VERSION_DRIFT_MAJOR",
      description: `Source package.json is ${packageName}@${localVersion} but the npm registry 'latest' is ${registryLatest} (${gap} major version${gap > 1 ? "s" : ""} ahead). The published package may not correspond to this source - the code you audit here is not what 'npm install' delivers.`,
      severity: "medium",
      file: "package.json",
      match: `${localVersion} (source) vs ${registryLatest} (npm latest)`,
      confidence: 0.6,
      category: "supply-chain",
      recommendation: `Verify why the source and the published 'latest' diverge by a major version. Confirm the npm ${registryLatest} artifact was built from auditable source (a matching tag/commit), not from a branch or machine you cannot inspect. A source-vs-registry major gap can indicate an unauthorized publish, or that review is happening against the wrong revision.`,
    };
  }

  return null;
}

/**
 * Fetch the 'latest' dist-tag for a package from the npm registry.
 * Resolves to null on any error/timeout/non-200 (never throws) so callers stay
 * offline-safe. Exposed for injection in tests.
 */
export function fetchNpmLatest(packageName: string): Promise<string | null> {
  const encodedName = packageName.startsWith("@")
    ? `@${packageName.slice(1).replace("/", "%2F")}`
    : encodeURIComponent(packageName);
  const url = `${NPM_REGISTRY_URL}/${encodedName}`;

  return new Promise((resolve) => {
    const req = https.get(
      url,
      { headers: { Accept: "application/json", "User-Agent": "supply-chain-guard" }, timeout: 5000 },
      (res) => {
        if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
        let data = "";
        res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
        res.on("end", () => {
          try {
            const json = JSON.parse(data) as { "dist-tags"?: Record<string, string> };
            resolve(json["dist-tags"]?.latest ?? null);
          } catch { resolve(null); }
        });
      },
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => { req.destroy(); resolve(null); });
  });
}

/**
 * Read the local package.json name+version and compare against the registry
 * 'latest'. The fetcher is injectable so unit tests never touch the network.
 * Returns [] (and never throws) when there is no package.json, no name/version,
 * or the registry is unreachable - preserving the offline-safe default.
 */
export async function checkRegistryVersionDrift(
  projectDir: string,
  fetchLatest: (name: string) => Promise<string | null> = fetchNpmLatest,
): Promise<Finding[]> {
  const pkgPath = path.join(projectDir, "package.json");
  if (!fs.existsSync(pkgPath)) return [];

  let pkg: { name?: unknown; version?: unknown };
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  } catch {
    return [];
  }
  if (typeof pkg.name !== "string" || typeof pkg.version !== "string") return [];

  let latest: string | null;
  try {
    latest = await fetchLatest(pkg.name);
  } catch {
    return []; // offline / registry error: skip
  }
  if (!latest) return [];

  const finding = evaluateVersionDrift(pkg.name, pkg.version, latest);
  return finding ? [finding] : [];
}

/**
 * Extract version metadata from npm registry response.
 * Expects the full package metadata from https://registry.npmjs.org/<package>
 */
export function extractVersionMeta(
  registryData: Record<string, unknown>,
): NpmVersionMeta[] {
  const versions = registryData.versions as Record<string, Record<string, unknown>> | undefined;
  const time = registryData.time as Record<string, string> | undefined;

  if (!versions || !time) return [];

  const result: NpmVersionMeta[] = [];

  for (const [ver, meta] of Object.entries(versions)) {
    const scripts = meta.scripts as Record<string, string> | undefined;
    const maintainers = (meta.maintainers as Array<{ name?: string }> | undefined) ?? [];
    const dist = meta.dist as { tarball?: string } | undefined;

    result.push({
      version: ver,
      publishedAt: time[ver] ?? "",
      maintainers: maintainers.map((m) => m.name ?? "unknown"),
      hasInstallScripts: !!(scripts?.preinstall || scripts?.postinstall || scripts?.install),
      tarballUrl: dist?.tarball ?? "",
    });
  }

  return result;
}
