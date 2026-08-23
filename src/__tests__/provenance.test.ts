import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import { formatReport } from "../reporter.js";
import { scan } from "../scanner.js";
import { FEED_GENERATED_AT } from "../threat-intel.js";
import type { ScanReport, DetectionSetProvenance } from "../types.js";

const FORMATS = [
  "text",
  "json",
  "markdown",
  "sarif",
  "sbom",
  "html",
  "badge",
  "gitlab",
  "junit",
] as const;

function createSampleReport(overrides?: Partial<ScanReport>): ScanReport {
  const detectionSet: DetectionSetProvenance = {
    bundledVersion: "5.28.1",
    bundledEntryCount: 13046,
    generatedAt: "2026-08-23T00:00:00.000Z",
    cacheMerged: false,
    effectiveEntryCount: 13046,
  };

  return {
    tool: "supply-chain-guard v5.28.1",
    timestamp: "2026-08-23T12:34:56.789Z",
    target: "test-target",
    scanType: "directory",
    durationMs: 42,
    score: 0,
    riskLevel: "clean",
    summary: {
      totalFiles: 10,
      filesScanned: 10,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    findings: [],
    recommendations: [],
    commit: "437a27cdc7554ad4fa2de51a25e20066c7e9ef3b",
    branch: "main",
    repositoryUri: "https://github.com/homeofe/supply-chain-guard",
    detectionSet,
    ...overrides,
  };
}

describe("Issue #208 - Provenance metadata across all report formats", () => {
  it("every report format states the tool version", () => {
    const report = createSampleReport();
    for (const fmt of FORMATS) {
      const output = formatReport(report, fmt);
      expect(
        output.includes("5.28.1") || output.includes("supply-chain-guard"),
        `Format "${fmt}" must state tool version`,
      ).toBe(true);

      // Verify specific format representations
      if (fmt === "sarif") {
        const sarif = JSON.parse(output);
        expect(sarif.runs[0].tool.driver.version).toBe("5.28.1");
      } else if (fmt === "junit") {
        expect(output).toContain('property name="supply-chain-guard:tool-version" value="supply-chain-guard v5.28.1"');
      } else if (fmt === "badge") {
        const badge = JSON.parse(output);
        expect(badge.version || badge.tool).toBeDefined();
      } else if (fmt === "markdown") {
        expect(output).toContain("| Tool | `supply-chain-guard v5.28.1` |");
      }
    }
  });

  it("every report format states a scan timestamp (including SARIF invocations and JUnit)", () => {
    const report = createSampleReport();
    const ts = report.timestamp;

    for (const fmt of FORMATS) {
      const output = formatReport(report, fmt);
      if (fmt === "gitlab") {
        // GitLab uses seconds-resolution ISO timestamp (YYYY-MM-DDTHH:MM:SS)
        expect(output).toContain("2026-08-23T12:34:56");
      } else {
        expect(output, `Format "${fmt}" must state timestamp ${ts}`).toContain(ts);
      }

      if (fmt === "sarif") {
        const sarif = JSON.parse(output);
        expect(sarif.runs[0].invocations[0].startTimeUtc).toBe(ts);
        expect(sarif.runs[0].invocations[0].endTimeUtc).toBe(ts);
      } else if (fmt === "junit") {
        expect(output).toContain(`timestamp="${ts}"`);
        expect(output).toContain(`property name="supply-chain-guard:timestamp" value="${ts}"`);
      }
    }
  });

  it("every report format captures the scanned tree's revision when present", () => {
    const report = createSampleReport();
    const commitSha = report.commit!;

    for (const fmt of FORMATS) {
      const output = formatReport(report, fmt);
      expect(output, `Format "${fmt}" must include commit ${commitSha}`).toContain(commitSha);

      if (fmt === "sarif") {
        const sarif = JSON.parse(output);
        expect(sarif.runs[0].versionControlProvenance).toBeDefined();
        expect(sarif.runs[0].versionControlProvenance[0].revisionId).toBe(commitSha);
      } else if (fmt === "junit") {
        expect(output).toContain(`property name="supply-chain-guard:commit" value="${commitSha}"`);
      } else if (fmt === "sbom") {
        const sbom = JSON.parse(output);
        const commitProp = sbom.metadata.properties.find(
          (p: { name: string }) => p.name === "supply-chain-guard:commit",
        );
        expect(commitProp?.value).toBe(commitSha);
      }
    }
  });

  it("plainly states absent/non-git when scanned tree is not a git repository", () => {
    const report = createSampleReport({ commit: undefined, branch: undefined, repositoryUri: undefined });

    const textOutput = formatReport(report, "text");
    expect(textOutput).toContain("[not a git repository]");

    const mdOutput = formatReport(report, "markdown");
    expect(mdOutput).toContain("none (not a git repository)");

    const sarifOutput = formatReport(report, "sarif");
    const sarif = JSON.parse(sarifOutput);
    expect(sarif.runs[0].versionControlProvenance).toBeUndefined();

    const junitOutput = formatReport(report, "junit");
    expect(junitOutput).toContain('property name="supply-chain-guard:commit" value="none (not a git repository)"');

    const sbomOutput = formatReport(report, "sbom");
    const sbom = JSON.parse(sbomOutput);
    const commitProp = sbom.metadata.properties.find(
      (p: { name: string }) => p.name === "supply-chain-guard:commit",
    );
    expect(commitProp?.value).toBe("none (not a git repository)");

    const gitlabOutput = formatReport(report, "gitlab");
    expect(gitlabOutput).toContain("Commit: none (not a git repository)");
  });

  it("every report format captures the detection set metadata (version, entry count, generation timestamp)", () => {
    const report = createSampleReport();

    for (const fmt of FORMATS) {
      const output = formatReport(report, fmt);
      expect(output, `Format "${fmt}" must state detection set version or entry count`).toMatch(/13046|5\.28\.1/);

      if (fmt === "sarif") {
        const sarif = JSON.parse(output);
        expect(sarif.runs[0].properties.detectionSet).toEqual(report.detectionSet);
      } else if (fmt === "junit") {
        expect(output).toContain('property name="supply-chain-guard:detection-set:version" value="5.28.1"');
        expect(output).toContain('property name="supply-chain-guard:detection-set:entry-count" value="13046"');
        expect(output).toContain('property name="supply-chain-guard:detection-set:generated-at" value="2026-08-23T00:00:00.000Z"');
        expect(output).toContain('property name="supply-chain-guard:detection-set:cache-merged" value="false"');
      } else if (fmt === "sbom") {
        const sbom = JSON.parse(output);
        const dsVer = sbom.metadata.properties.find(
          (p: { name: string }) => p.name === "supply-chain-guard:detection-set:version",
        );
        expect(dsVer?.value).toBe("5.28.1");
        const dsCount = sbom.metadata.properties.find(
          (p: { name: string }) => p.name === "supply-chain-guard:detection-set:entry-count",
        );
        expect(dsCount?.value).toBe("13046");
        const dsGen = sbom.metadata.properties.find(
          (p: { name: string }) => p.name === "supply-chain-guard:detection-set:generated-at",
        );
        expect(dsGen?.value).toBe("2026-08-23T00:00:00.000Z");
      }
    }
  });

  it("distinguishes a scan with a refreshed merged cache from bundled feed alone", () => {
    const bundledOnlyReport = createSampleReport({
      detectionSet: {
        bundledVersion: "5.28.1",
        bundledEntryCount: 13046,
        generatedAt: "2026-08-23T00:00:00.000Z",
        cacheMerged: false,
        effectiveEntryCount: 13046,
      },
    });

    const mergedCacheReport = createSampleReport({
      detectionSet: {
        bundledVersion: "5.28.1",
        bundledEntryCount: 13046,
        generatedAt: "2026-08-23T00:00:00.000Z",
        cacheMerged: true,
        effectiveEntryCount: 13100,
        cachePath: "/path/to/.scg-cache/threat-feed.json",
        cacheRefreshedAt: "2026-08-23T11:00:00.000Z",
      },
    });

    const bundledText = formatReport(bundledOnlyReport, "text");
    const mergedText = formatReport(mergedCacheReport, "text");
    expect(bundledText).not.toContain("merged cache");
    expect(mergedText).toContain("merged cache");

    const bundledJunit = formatReport(bundledOnlyReport, "junit");
    const mergedJunit = formatReport(mergedCacheReport, "junit");
    expect(bundledJunit).toContain('property name="supply-chain-guard:detection-set:cache-merged" value="false"');
    expect(mergedJunit).toContain('property name="supply-chain-guard:detection-set:cache-merged" value="true"');

    const bundledSbom = JSON.parse(formatReport(bundledOnlyReport, "sbom"));
    const mergedSbom = JSON.parse(formatReport(mergedCacheReport, "sbom"));
    const bundledCacheProp = bundledSbom.metadata.properties.find(
      (p: { name: string }) => p.name === "supply-chain-guard:detection-set:cache-merged",
    );
    const mergedCacheProp = mergedSbom.metadata.properties.find(
      (p: { name: string }) => p.name === "supply-chain-guard:detection-set:cache-merged",
    );
    expect(bundledCacheProp.value).toBe("false");
    expect(mergedCacheProp.value).toBe("true");
  });

  it("feed.json carries a generation timestamp distinct from the package version", () => {
    const feedPath = path.resolve(__dirname, "../../feed.json");
    const feedJson = JSON.parse(fs.readFileSync(feedPath, "utf-8"));

    expect(feedJson.generatedAt).toBeDefined();
    expect(feedJson.generatedAt).toBe(FEED_GENERATED_AT);
    expect(typeof feedJson.generatedAt).toBe("string");
    expect(feedJson.version).toBe("5.28.1");
  });

  it("integration: scan() captures git provenance from a git working tree and marks non-git clean", async () => {
    const tmpGit = fs.mkdtempSync(path.join(os.tmpdir(), "scg-git-test-"));
    const tmpNonGit = fs.mkdtempSync(path.join(os.tmpdir(), "scg-nongit-test-"));

    try {
      fs.writeFileSync(path.join(tmpGit, "package.json"), JSON.stringify({ name: "git-test", version: "1.0.0" }));
      execSync("git init -q && git config user.name test && git config user.email test@example.com && git add -A && git commit -qm test-commit", {
        cwd: tmpGit,
        stdio: "ignore",
      });
      const gitHead = execSync("git rev-parse HEAD", { cwd: tmpGit, encoding: "utf-8" }).trim();

      fs.writeFileSync(path.join(tmpNonGit, "package.json"), JSON.stringify({ name: "nongit-test", version: "1.0.0" }));

      const gitReport = await scan({ target: tmpGit, scanType: "directory" });
      expect(gitReport.commit).toBe(gitHead);
      expect(gitReport.detectionSet).toBeDefined();
      expect(gitReport.detectionSet?.bundledVersion).toBe("5.28.1");

      const nonGitReport = await scan({ target: tmpNonGit, scanType: "directory" });
      expect(nonGitReport.commit).toBeUndefined();
      expect(nonGitReport.detectionSet).toBeDefined();
    } finally {
      fs.rmSync(tmpGit, { recursive: true, force: true });
      fs.rmSync(tmpNonGit, { recursive: true, force: true });
    }
  });
});
