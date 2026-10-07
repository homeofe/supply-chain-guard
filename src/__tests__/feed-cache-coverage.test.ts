import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { getReportExitCode, formatReport } from "../reporter.js";
import { FEED_CACHE_FILE, resetThreatIntelCache } from "../threat-intel.js";

const dirs: string[] = [];
afterEach(() => {
  resetThreatIntelCache();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function fixture(): { project: string; cache: string; cacheFile: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-feed-coverage-"));
  dirs.push(root);
  const project = path.join(root, "project");
  const cache = path.join(root, "cache");
  fs.mkdirSync(project);
  fs.mkdirSync(cache);
  fs.writeFileSync(path.join(project, "index.js"), 'const endpoint = "https://audit-control.example";\n');
  return { project, cache, cacheFile: path.join(cache, FEED_CACHE_FILE) };
}

function cacheDocument(timestamp: string): string {
  return JSON.stringify({
    timestamp,
    unsigned: true,
    entries: [{
      type: "domain",
      value: "audit-control.example",
      severity: "critical",
      confidence: 1,
      family: "Synthetic Test",
    }],
  });
}

describe("refreshed feed cache coverage", () => {
  it("marks a corrupt existing cache partial instead of returning a clean verdict", async () => {
    const { project, cache, cacheFile } = fixture();
    fs.writeFileSync(cacheFile, cacheDocument(new Date().toISOString()));
    const valid = await scan({ target: project, format: "json", cacheDir: cache, noHistory: true });
    expect(valid.findings.map((finding) => finding.rule)).toContain("THREAT_INTEL_MATCH");

    fs.writeFileSync(cacheFile, "{broken");
    resetThreatIntelCache();
    const corrupt = await scan({ target: project, format: "json", cacheDir: cache, noHistory: true });
    expect(corrupt.findings.map((finding) => finding.rule)).toContain("THREAT_FEED_CACHE_UNREADABLE");
    expect(corrupt.findings.map((finding) => finding.rule)).not.toContain("THREAT_INTEL_MATCH");
    expect(corrupt.partialScan).toBe(true);
    expect(getReportExitCode(corrupt)).not.toBe(0);
    expect(formatReport(corrupt, "sarif")).toContain("THREAT_FEED_CACHE_UNREADABLE");
  });

  it("reports an expired but merged cache as merged in JSON and SARIF", async () => {
    const { project, cache, cacheFile } = fixture();
    const timestamp = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
    fs.writeFileSync(cacheFile, cacheDocument(timestamp));

    const report = await scan({ target: project, format: "json", cacheDir: cache, noHistory: true });
    expect(report.findings.map((finding) => finding.rule)).toContain("THREAT_INTEL_MATCH");
    expect(report.detectionSet?.cacheMerged).toBe(true);
    expect(report.detectionSet?.cacheRefreshedAt).toBe(timestamp);
    expect(JSON.parse(formatReport(report, "json")).detectionSet.cacheMerged).toBe(true);
    expect(JSON.parse(formatReport(report, "sarif")).runs[0].properties.detectionSet.cacheMerged).toBe(true);
  });
});
