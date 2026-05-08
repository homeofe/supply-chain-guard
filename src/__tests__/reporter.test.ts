import { describe, it, expect } from "vitest";
import { formatReport } from "../reporter.js";
import type { ScanReport } from "../types.js";

/** Strip ANSI escape codes for plain-text assertions */
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

/** Build a fixture ScanReport with findings of every severity */
function makeReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    tool: "supply-chain-guard@3.1.0",
    timestamp: "2026-03-26T10:00:00.000Z",
    target: "test-package",
    scanType: "npm",
    durationMs: 42,
    findings: [
      {
        rule: "EVIL_CRITICAL",
        description: "Critical evil thing",
        severity: "critical",
        file: "index.js",
        line: 5,
        match: "eval(atob(x))",
        recommendation: "Remove the eval call",
      },
      {
        rule: "EVIL_HIGH",
        description: "High evil thing",
        severity: "high",
        file: "lib/util.js",
        recommendation: "Fix the high issue",
      },
      {
        rule: "EVIL_MEDIUM",
        description: "Medium concern",
        severity: "medium",
        recommendation: "Consider fixing",
      },
      {
        rule: "EVIL_LOW",
        description: "Low concern",
        severity: "low",
        recommendation: "Nice to fix",
      },
      {
        rule: "EVIL_INFO",
        description: "Info note",
        severity: "info",
        recommendation: "FYI",
      },
    ],
    summary: {
      totalFiles: 10,
      filesScanned: 8,
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
      info: 1,
    },
    score: 52,
    riskLevel: "high",
    recommendations: ["Remove the package", "Audit dependencies"],
    ...overrides,
  };
}

function makeEmptyReport(): ScanReport {
  return makeReport({
    findings: [],
    summary: { totalFiles: 5, filesScanned: 5, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    score: 0,
    riskLevel: "clean",
    recommendations: [],
  });
}

// ─── JSON format ──────────────────────────────────────────────────────────────

describe("formatReport – JSON", () => {
  it("should produce valid JSON", () => {
    const output = formatReport(makeReport(), "json");
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("should contain all top-level fields", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "json")) as ScanReport;
    expect(parsed).toHaveProperty("tool");
    expect(parsed).toHaveProperty("timestamp");
    expect(parsed).toHaveProperty("target");
    expect(parsed).toHaveProperty("findings");
    expect(parsed).toHaveProperty("summary");
    expect(parsed).toHaveProperty("score");
    expect(parsed).toHaveProperty("riskLevel");
    expect(parsed).toHaveProperty("recommendations");
  });

  it("should serialize all findings with correct severity values", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "json")) as ScanReport;
    const severities = parsed.findings.map((f) => f.severity);
    expect(severities).toContain("critical");
    expect(severities).toContain("high");
    expect(severities).toContain("medium");
    expect(severities).toContain("low");
    expect(severities).toContain("info");
  });

  it("should produce empty findings array for empty report", () => {
    const parsed = JSON.parse(formatReport(makeEmptyReport(), "json")) as ScanReport;
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.score).toBe(0);
    expect(parsed.riskLevel).toBe("clean");
  });

  it("should preserve finding fields (rule, file, line, match)", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "json")) as ScanReport;
    const critical = parsed.findings.find((f) => f.rule === "EVIL_CRITICAL");
    expect(critical?.file).toBe("index.js");
    expect(critical?.line).toBe(5);
    expect(critical?.match).toBe("eval(atob(x))");
    expect(critical?.recommendation).toBe("Remove the eval call");
  });
});

// ─── SARIF format ─────────────────────────────────────────────────────────────

interface SarifOutput {
  $schema: string;
  version: string;
  runs: Array<{
    tool: { driver: { name: string; rules: Array<{ id: string; defaultConfiguration: { level: string } }> } };
    results: Array<{
      ruleId: string;
      level: string;
      message: { text: string };
      locations?: Array<{ physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } } }>;
    }>;
  }>;
}

describe("formatReport – SARIF", () => {
  it("should produce valid JSON", () => {
    const output = formatReport(makeReport(), "sarif");
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("should have SARIF 2.1.0 schema and version", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sarif")) as SarifOutput;
    expect(parsed.$schema).toContain("sarif");
    expect(parsed.version).toBe("2.1.0");
  });

  it("should have runs array with one entry", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sarif")) as SarifOutput;
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.name).toBe("supply-chain-guard");
  });

  it("should map critical/high findings to SARIF level error", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sarif")) as SarifOutput;
    const results = parsed.runs[0].results;
    const critResult = results.find((r) => r.ruleId === "EVIL_CRITICAL");
    const highResult = results.find((r) => r.ruleId === "EVIL_HIGH");
    expect(critResult?.level).toBe("error");
    expect(highResult?.level).toBe("error");
  });

  it("should map medium finding to SARIF level warning", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sarif")) as SarifOutput;
    const results = parsed.runs[0].results;
    const medResult = results.find((r) => r.ruleId === "EVIL_MEDIUM");
    expect(medResult?.level).toBe("warning");
  });

  it("should map low/info findings to SARIF level note", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sarif")) as SarifOutput;
    const results = parsed.runs[0].results;
    const lowResult = results.find((r) => r.ruleId === "EVIL_LOW");
    const infoResult = results.find((r) => r.ruleId === "EVIL_INFO");
    expect(lowResult?.level).toBe("note");
    expect(infoResult?.level).toBe("note");
  });

  it("should include physicalLocation with uri and line for findings with file+line", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sarif")) as SarifOutput;
    const results = parsed.runs[0].results;
    const critResult = results.find((r) => r.ruleId === "EVIL_CRITICAL");
    expect(critResult?.locations?.[0].physicalLocation.artifactLocation.uri).toBe("index.js");
    expect(critResult?.locations?.[0].physicalLocation.region?.startLine).toBe(5);
  });

  it("should have rules in driver matching all unique rule IDs", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sarif")) as SarifOutput;
    const ruleIds = parsed.runs[0].tool.driver.rules.map((r) => r.id);
    expect(ruleIds).toContain("EVIL_CRITICAL");
    expect(ruleIds).toContain("EVIL_HIGH");
    expect(ruleIds).toContain("EVIL_MEDIUM");
  });

  it("should produce empty results for empty report", () => {
    const parsed = JSON.parse(formatReport(makeEmptyReport(), "sarif")) as SarifOutput;
    expect(parsed.runs[0].results).toHaveLength(0);
    expect(parsed.runs[0].tool.driver.rules).toHaveLength(0);
  });
});

// ─── Markdown format ──────────────────────────────────────────────────────────

describe("formatReport – Markdown", () => {
  it("should contain a top-level header", () => {
    const output = formatReport(makeReport(), "markdown");
    expect(output).toContain("## 🛡️ supply-chain-guard Scan Report");
  });

  it("should include target and score in metadata table", () => {
    const output = formatReport(makeReport(), "markdown");
    expect(output).toContain("test-package");
    expect(output).toContain("52/100");
  });

  it("should include findings section with severity badges", () => {
    const output = formatReport(makeReport(), "markdown");
    expect(output).toContain("### Findings");
    expect(output).toContain("[CRITICAL]");
    expect(output).toContain("[HIGH]");
  });

  it("should include rule IDs in findings", () => {
    const output = formatReport(makeReport(), "markdown");
    expect(output).toContain("EVIL_CRITICAL");
    expect(output).toContain("EVIL_HIGH");
  });

  it("should show summary badge counts when there are findings", () => {
    const output = formatReport(makeReport(), "markdown");
    expect(output).toContain("1 critical");
    expect(output).toContain("1 high");
  });

  it("should show clean message for empty report", () => {
    const output = formatReport(makeEmptyReport(), "markdown");
    expect(output).toContain("No malicious indicators detected");
  });

  it("should include recommendations section", () => {
    const output = formatReport(makeReport(), "markdown");
    expect(output).toContain("### Recommendations");
    expect(output).toContain("Remove the package");
  });

  it("should include file paths in findings", () => {
    const output = formatReport(makeReport(), "markdown");
    expect(output).toContain("index.js:5");
    expect(output).toContain("lib/util.js");
  });
});

// ─── Text format ──────────────────────────────────────────────────────────────

describe("formatReport – Text", () => {
  it("should contain scan report header (stripped ANSI)", () => {
    const output = stripAnsi(formatReport(makeReport(), "text"));
    expect(output).toContain("supply-chain-guard");
    expect(output).toContain("v5.2.8");
  });

  it("should show risk score", () => {
    const output = stripAnsi(formatReport(makeReport(), "text"));
    expect(output).toContain("52 / 100");
    expect(output).toContain("HIGH");
  });

  it("should list findings with severity tags", () => {
    const output = stripAnsi(formatReport(makeReport(), "text"));
    expect(output).toContain("[CRITICAL]");
    expect(output).toContain("[HIGH]");
    expect(output).toContain("EVIL_CRITICAL");
  });

  it("should show file and line number in findings", () => {
    const output = stripAnsi(formatReport(makeReport(), "text"));
    expect(output).toContain("index.js:5");
  });

  it("should show matched content", () => {
    const output = stripAnsi(formatReport(makeReport(), "text"));
    expect(output).toContain("eval(atob(x))");
  });

  it("should show recommendations", () => {
    const output = stripAnsi(formatReport(makeReport(), "text"));
    expect(output).toContain("Remove the package");
    expect(output).toContain("Audit dependencies");
  });

  it("should show clean message for empty findings", () => {
    const output = stripAnsi(formatReport(makeEmptyReport(), "text"));
    expect(output).toContain("No findings");
  });
});

// ─── SBOM format ──────────────────────────────────────────────────────────────

interface SbomOutput {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { components: Array<{ name: string }> };
    component: { name: string };
  };
  components: Array<{ name: string; "bom-ref": string }>;
  vulnerabilities: Array<{
    "bom-ref": string;
    id: string;
    ratings: Array<{ severity: string }>;
    description: string;
    affects: Array<{ ref: string }>;
  }>;
}

describe("formatReport – SBOM (CycloneDX 1.6)", () => {
  it("should produce valid JSON", () => {
    const output = formatReport(makeReport(), "sbom");
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("should set bomFormat to CycloneDX and specVersion to 1.6", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    expect(parsed.bomFormat).toBe("CycloneDX");
    expect(parsed.specVersion).toBe("1.6");
  });

  it("should include a serialNumber as urn:uuid", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    expect(parsed.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  });

  it("should set metadata.component.name to the scan target", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    expect(parsed.metadata.component.name).toBe("test-package");
  });

  it("should list supply-chain-guard in metadata.tools", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    const toolNames = parsed.metadata.tools.components.map((c) => c.name);
    expect(toolNames).toContain("supply-chain-guard");
  });

  it("should map every finding to a vulnerability entry", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    expect(parsed.vulnerabilities).toHaveLength(5);
    const ids = parsed.vulnerabilities.map((v) => v.id);
    expect(ids).toContain("EVIL_CRITICAL");
    expect(ids).toContain("EVIL_HIGH");
    expect(ids).toContain("EVIL_MEDIUM");
  });

  it("should preserve severity in vulnerability ratings", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    const critVuln = parsed.vulnerabilities.find((v) => v.id === "EVIL_CRITICAL");
    expect(critVuln?.ratings[0].severity).toBe("critical");
  });

  it("should have empty vulnerabilities array for empty report", () => {
    const parsed = JSON.parse(formatReport(makeEmptyReport(), "sbom")) as SbomOutput;
    expect(parsed.vulnerabilities).toHaveLength(0);
  });

  it("should include components array (empty in fallback mode, no lockfile)", () => {
    // In v4.9, components are populated from package-lock.json via sbomDocument.
    // The fallback SBOM (no sbomDocument on report) has an empty components array.
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    expect(Array.isArray(parsed.components)).toBe(true);
  });

  it("each vulnerability should reference the target component", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "sbom")) as SbomOutput;
    for (const vuln of parsed.vulnerabilities) {
      expect(vuln.affects[0].ref).toBe("target");
    }
  });
});
