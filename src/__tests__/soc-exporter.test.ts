import { describe, it, expect } from "vitest";
import { exportIncidentBundle, exportIncidentMarkdown, exportCsvSummary } from "../soc-exporter.js";
import type { ScanReport } from "../types.js";

function makeReport(
  findings: ScanReport["findings"] = [],
  overrides: Partial<ScanReport> = {},
): ScanReport {
  return {
    tool: "supply-chain-guard v4.6.0",
    timestamp: "2026-04-04T12:00:00Z",
    target: "./test-project",
    scanType: "directory",
    durationMs: 100,
    findings,
    summary: {
      totalFiles: 10, filesScanned: 8,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: 0, low: 0, info: 0,
    },
    score: 50,
    riskLevel: "high",
    recommendations: ["Test recommendation"],
    incidents: [{
      id: "test-1", name: "Test Incident", severity: "critical",
      confidence: 0.9, findings: [], narrative: "Test narrative", indicators: ["RULE_1"],
    }],
    remediations: [{
      id: "rem-1", title: "Fix it", description: "Do the thing",
      priority: "critical", category: "dependency", steps: ["Step 1"], automated: false,
    }],
    ...overrides,
  };
}

function makePartialReport(): ScanReport {
  return makeReport([], {
    score: 0,
    riskLevel: "clean",
    incidents: [],
    remediations: [],
    partialScan: true,
  });
}

describe("SOC Exporter", () => {
  describe("exportIncidentBundle", () => {
    it("should produce valid JSON", () => {
      const json = exportIncidentBundle(makeReport());
      expect(() => JSON.parse(json)).not.toThrow();
    });

    it("should include schema and scanner version", () => {
      const bundle = JSON.parse(exportIncidentBundle(makeReport()));
      expect(bundle.schema).toBe("supply-chain-guard-incident/1.0");
      expect(bundle.scannerVersion).toContain("supply-chain-guard");
    });

    it("should include incidents", () => {
      const bundle = JSON.parse(exportIncidentBundle(makeReport()));
      expect(bundle.incidents).toHaveLength(1);
      expect(bundle.incidents[0].name).toBe("Test Incident");
    });

    it("should include remediations", () => {
      const bundle = JSON.parse(exportIncidentBundle(makeReport()));
      expect(bundle.remediations).toHaveLength(1);
    });

    it("marks partial reports as incomplete without emitting a clean verdict", () => {
      const bundle = JSON.parse(exportIncidentBundle(makePartialReport()));

      expect(bundle.partialScan).toBe(true);
      expect(bundle.riskLevel).toBe("unknown");
      expect(bundle.riskLevel).not.toBe("clean");
    });

    it("preserves the existing risk level and shape for complete reports", () => {
      const bundle = JSON.parse(exportIncidentBundle(makeReport()));

      expect(bundle.partialScan).toBeUndefined();
      expect(bundle.riskLevel).toBe("high");
    });
  });

  describe("exportIncidentMarkdown", () => {
    it("should produce markdown with headers", () => {
      const md = exportIncidentMarkdown(makeReport());
      expect(md).toContain("# Supply Chain Security Incident Report");
      expect(md).toContain("## Detected Incidents");
    });

    it("should include remediation steps", () => {
      const md = exportIncidentMarkdown(makeReport());
      expect(md).toContain("## Recommended Actions");
    });

    it("warns visibly when a partial report cannot support a clean verdict", () => {
      const md = exportIncidentMarkdown(makePartialReport());

      expect(md).toContain("(UNKNOWN; PARTIAL SCAN)");
      expect(md).toContain("**Scan incomplete:**");
      expect(md).toContain("this is not a clean verdict");
      expect(md).not.toContain("(CLEAN)");
    });

    it("preserves the existing risk line for complete reports", () => {
      const md = exportIncidentMarkdown(makeReport());

      expect(md).toContain("**Risk Score:** 50/100 (HIGH)");
      expect(md).not.toContain("PARTIAL SCAN");
      expect(md).not.toContain("Scan incomplete");
    });
  });

  describe("exportCsvSummary", () => {
    it("should produce CSV with coverage status", () => {
      const csv = exportCsvSummary(makeReport([
        { rule: "TEST_RULE", severity: "high", description: "Test finding", recommendation: "Fix" },
      ]));
      expect(csv).toContain(
        "rule,severity,confidence,file,description,scan_status,partial_scan",
      );
      expect(csv).toContain("TEST_RULE");
      expect(csv).toContain('"complete","false"');
    });

    it("distinguishes an empty partial scan from an empty completed scan", () => {
      const partial = exportCsvSummary(makePartialReport());
      const complete = exportCsvSummary(makeReport([], {
        score: 0,
        riskLevel: "clean",
        incidents: [],
        remediations: [],
      }));

      expect(partial).toContain('"partial","true"');
      expect(complete).toContain('"complete","false"');
      expect(partial).not.toBe(complete);
    });
  });
});
