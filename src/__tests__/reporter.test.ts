import { describe, it, expect } from "vitest";
import { formatReport } from "../reporter.js";
import type { ScanReport } from "../types.js";
import pkg from "../../package.json";

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
    // Read the version from package.json instead of hardcoding it - this
    // test broke twice on releases (v5.2.14, v5.2.17) because the string
    // here was forgotten when bumping versions elsewhere.
    expect(output).toContain(`v${pkg.version}`);
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

// ─── Badge format (Shields.io endpoint) ───────────────────────────────────────

interface BadgeOutput {
  schemaVersion: number;
  label: string;
  message: string;
  color: string;
}

describe("formatReport – Badge (Shields.io endpoint)", () => {
  it("should produce valid JSON", () => {
    const output = formatReport(makeReport(), "badge");
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("should have schemaVersion 1 and the supply-chain-guard label", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "badge")) as BadgeOutput;
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.label).toBe("supply-chain-guard");
  });

  // v5.5.0 MF-2: the badge derives from the findings SUMMARY, mirroring the
  // CLI exit-code semantics - NOT from the score-based riskLevel (a single
  // critical scores ~25 points = riskLevel "medium", which used to render a
  // yellow badge while the gate exited 2).
  const summaryOf = (c: number, h: number, m: number, l: number, i = 0) => ({
    totalFiles: 1, filesScanned: 1,
    critical: c, high: h, medium: m, low: l, info: i,
  });

  it("renders clean/brightgreen when the summary has no findings", () => {
    const parsed = JSON.parse(
      formatReport(makeReport({ summary: summaryOf(0, 0, 0, 0) }), "badge"),
    ) as BadgeOutput;
    expect(parsed.message).toBe("clean");
    expect(parsed.color).toBe("brightgreen");
  });

  it("renders low counts brightgreen", () => {
    const parsed = JSON.parse(
      formatReport(makeReport({ summary: summaryOf(0, 0, 0, 3) }), "badge"),
    ) as BadgeOutput;
    expect(parsed.message).toBe("3 low");
    expect(parsed.color).toBe("brightgreen");
  });

  it("renders medium counts yellow", () => {
    const parsed = JSON.parse(
      formatReport(makeReport({ summary: summaryOf(0, 0, 2, 5) }), "badge"),
    ) as BadgeOutput;
    expect(parsed.message).toBe("2 medium");
    expect(parsed.color).toBe("yellow");
  });

  it("renders high counts orange", () => {
    const parsed = JSON.parse(
      formatReport(makeReport({ summary: summaryOf(0, 4, 2, 0) }), "badge"),
    ) as BadgeOutput;
    expect(parsed.message).toBe("4 high");
    expect(parsed.color).toBe("orange");
  });

  it("renders critical counts red", () => {
    const parsed = JSON.parse(
      formatReport(makeReport({ summary: summaryOf(1, 4, 2, 0) }), "badge"),
    ) as BadgeOutput;
    expect(parsed.message).toBe("1 critical");
    expect(parsed.color).toBe("red");
  });

  it("MF-2 regression: ignores a calmer score-based riskLevel when criticals exist", () => {
    // One critical finding scores ~25 points -> riskLevel "medium". The badge
    // must still be red: it may never look calmer than the exit code.
    const report = makeReport({
      riskLevel: "medium",
      summary: summaryOf(1, 0, 0, 0),
    });
    const parsed = JSON.parse(formatReport(report, "badge")) as BadgeOutput;
    expect(parsed.message).toBe("1 critical");
    expect(parsed.color).toBe("red");
  });

  it("falls back to unknown/lightgrey when the summary is missing entirely", () => {
    const noSummary = makeReport({ summary: undefined as unknown as ScanReport["summary"] });
    const parsed = JSON.parse(formatReport(noSummary, "badge")) as BadgeOutput;
    expect(parsed.message).toBe("unknown");
    expect(parsed.color).toBe("lightgrey");
  });

  it("should not contain a trailing newline or extra fields", () => {
    const output = formatReport(makeReport(), "badge");
    const parsed = JSON.parse(output) as BadgeOutput;
    expect(output).toBe(JSON.stringify(parsed));
    expect(Object.keys(parsed).sort()).toEqual(["color", "label", "message", "schemaVersion"]);
  });
});

// ─── GitLab format (Dependency Scanning report) ───────────────────────────────

interface GitlabOutput {
  version: string;
  scan: {
    analyzer: { id: string; name: string; version: string; vendor: { name: string } };
    scanner: { id: string; name: string; version: string; vendor: { name: string } };
    type: string;
    start_time: string;
    end_time: string;
    status: string;
  };
  vulnerabilities: Array<{
    id: string;
    name: string;
    description: string;
    severity: string;
    solution: string;
    identifiers: Array<{ type: string; name: string; value: string }>;
    location: {
      file: string;
      dependency: { package: { name: string }; version: string };
    };
  }>;
}

describe("formatReport – GitLab (Dependency Scanning report)", () => {
  it("should produce valid JSON", () => {
    const output = formatReport(makeReport(), "gitlab");
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("should have schema version 15.2.4 and required top-level fields", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "gitlab")) as GitlabOutput;
    expect(parsed.version).toBe("15.2.4");
    expect(parsed).toHaveProperty("scan");
    expect(parsed).toHaveProperty("vulnerabilities");
    expect(Array.isArray(parsed.vulnerabilities)).toBe(true);
  });

  it("should identify supply-chain-guard as analyzer and scanner with pkg version", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "gitlab")) as GitlabOutput;
    expect(parsed.scan.type).toBe("dependency_scanning");
    expect(parsed.scan.status).toBe("success");
    for (const block of [parsed.scan.analyzer, parsed.scan.scanner]) {
      expect(block.id).toBe("supply_chain_guard");
      expect(block.name).toBe("supply-chain-guard");
      expect(block.vendor.name).toBe("supply-chain-guard");
      // Version must track package.json - hardcoding broke releases before
      // (v5.2.14, v5.2.17); the check:version-sync gate counts this string.
      expect(block.version).toBe(pkg.version);
    }
  });

  it("should format start_time/end_time without milliseconds or timezone suffix", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "gitlab")) as GitlabOutput;
    // Schema pattern: ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$
    const pattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/;
    expect(parsed.scan.start_time).toMatch(pattern);
    expect(parsed.scan.end_time).toMatch(pattern);
    expect(parsed.scan.start_time).toBe("2026-03-26T10:00:00");
  });

  it("should map internal severities to the GitLab enum", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "gitlab")) as GitlabOutput;
    const bySeverity = new Map(
      parsed.vulnerabilities.map((v) => [v.identifiers[0].value, v.severity]),
    );
    expect(bySeverity.get("EVIL_CRITICAL")).toBe("Critical");
    expect(bySeverity.get("EVIL_HIGH")).toBe("High");
    expect(bySeverity.get("EVIL_MEDIUM")).toBe("Medium");
    expect(bySeverity.get("EVIL_LOW")).toBe("Low");
    expect(bySeverity.get("EVIL_INFO")).toBe("Info");
  });

  it("should derive vulnerability id and identifiers from the rule", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "gitlab")) as GitlabOutput;
    const crit = parsed.vulnerabilities.find((v) => v.identifiers[0].value === "EVIL_CRITICAL");
    expect(crit?.id).toContain("EVIL_CRITICAL");
    expect(crit?.identifiers[0].type).toBe("supply_chain_guard_rule");
    expect(crit?.identifiers[0].name).toBe("EVIL_CRITICAL");
    // ids must be unique across all vulnerabilities
    const ids = parsed.vulnerabilities.map((v) => v.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("should set location.file from the finding and fall back to package.json", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "gitlab")) as GitlabOutput;
    const crit = parsed.vulnerabilities.find((v) => v.identifiers[0].value === "EVIL_CRITICAL");
    const med = parsed.vulnerabilities.find((v) => v.identifiers[0].value === "EVIL_MEDIUM");
    expect(crit?.location.file).toBe("index.js");
    // EVIL_MEDIUM has no file in the fixture
    expect(med?.location.file).toBe("package.json");
    expect(med?.location.dependency.package.name).toBe("test-package");
  });

  it("should carry description and recommendation as solution", () => {
    const parsed = JSON.parse(formatReport(makeReport(), "gitlab")) as GitlabOutput;
    const crit = parsed.vulnerabilities.find((v) => v.identifiers[0].value === "EVIL_CRITICAL");
    expect(crit?.description).toBe("Critical evil thing");
    expect(crit?.solution).toBe("Remove the eval call");
  });

  it("should produce a schema-valid report with zero vulnerabilities for an empty report", () => {
    const parsed = JSON.parse(formatReport(makeEmptyReport(), "gitlab")) as GitlabOutput;
    expect(parsed.version).toBe("15.2.4");
    expect(parsed.vulnerabilities).toHaveLength(0);
    expect(parsed.scan.status).toBe("success");
  });

  it("should report scan status failure for partial scans", () => {
    const parsed = JSON.parse(
      formatReport(makeReport({ partialScan: true }), "gitlab"),
    ) as GitlabOutput;
    expect(parsed.scan.status).toBe("failure");
  });
});

// ─── Markdown injection hardening ─────────────────────────────────────────────

describe("formatReport – markdown injection hardening", () => {
  it("neutralizes attacker-controlled scan content in the markdown report", () => {
    const md = formatReport(
      makeReport({
        target: "evil`pkg",
        findings: [
          {
            rule: "EVIL`RULE",
            description: "Heading <img src=x onerror=alert(1)>\n# Injected Heading",
            severity: "critical",
            file: "a.js",
            line: 1,
            match: "payload`); rm -rf ~\n# Fake Heading",
            recommendation: "Do <b>not</b> trust this",
          },
        ],
        summary: { totalFiles: 1, filesScanned: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      }),
      "markdown",
    );
    // HTML is escaped in plain-text fields, not left live.
    expect(md).not.toContain("<img");
    expect(md).toContain("&lt;img");
    // A backtick in scan content cannot close an inline code span.
    expect(md).not.toContain("payload`)");
    expect(md).toContain("payload')");
    // A newline in scan content cannot inject a new markdown line or header.
    expect(md).not.toContain("\n# Fake Heading");
    expect(md).not.toContain("\n# Injected Heading");
  });
});

// ─── Suppressed findings excluded from machine output ─────────────────────────

describe("formatReport – suppressed findings excluded from SARIF, SBOM and GitLab", () => {
  const reportWithSuppressed = makeReport({
    findings: [
      { rule: "ACTIVE_RULE", description: "active", severity: "high", recommendation: "fix", file: "a.js" },
      { rule: "SUPPRESSED_RULE", description: "policy-suppressed", severity: "high", recommendation: "fix", file: "b.js", suppressed: true },
    ],
  });

  it("omits suppressed findings from SARIF output", () => {
    const sarif = formatReport(reportWithSuppressed, "sarif");
    expect(sarif).toContain("ACTIVE_RULE");
    expect(sarif).not.toContain("SUPPRESSED_RULE");
  });

  it("omits suppressed findings from the fallback SBOM", () => {
    const sbom = formatReport(reportWithSuppressed, "sbom");
    expect(sbom).toContain("ACTIVE_RULE");
    expect(sbom).not.toContain("SUPPRESSED_RULE");
  });

  it("omits suppressed findings from the GitLab report", () => {
    const gitlab = formatReport(reportWithSuppressed, "gitlab");
    expect(gitlab).toContain("ACTIVE_RULE");
    expect(gitlab).not.toContain("SUPPRESSED_RULE");
  });
});
