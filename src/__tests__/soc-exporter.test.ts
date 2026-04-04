import { describe, it, expect } from "vitest";
import { exportIncidentBundle, exportIncidentMarkdown, exportCsvSummary } from "../soc-exporter.js";
import type { ScanReport } from "../types.js";

function makeReport(findings: ScanReport["findings"] = []): ScanReport {
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
  };
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
  });

  describe("exportCsvSummary", () => {
    it("should produce CSV with header", () => {
      const csv = exportCsvSummary(makeReport([
        { rule: "TEST_RULE", severity: "high", description: "Test finding", recommendation: "Fix" },
      ]));
      expect(csv).toContain("rule,severity,confidence,file,description");
      expect(csv).toContain("TEST_RULE");
    });
  });
});
