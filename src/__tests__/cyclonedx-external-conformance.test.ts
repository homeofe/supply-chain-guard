/**
 * CycloneDX 1.6 schema conformance tests for external threat intel and two-tier scoring.
 *
 * Validates that EPSS and CVSS ratings, CISA KEV analysis details, and two-tier
 * risk metadata strictly conform to the official CycloneDX 1.6 JSON Schema (bom-1.6.schema.json).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import Ajv, { type ValidateFunction } from "ajv";
import addFormats from "ajv-formats";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { generateSbomDocument } from "../sbom-generator.js";
import { formatReport } from "../reporter.js";
import type { Finding, ScanReport, SbomDocument, TwoTierVerdict } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = path.join(__dirname, "fixtures", "cyclonedx");

let validateBom: ValidateFunction;

beforeAll(() => {
  const load = (file: string) =>
    JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, file), "utf-8")) as object;

  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  for (const format of ["string", "iri-reference", "idn-email"]) {
    if (!ajv.formats[format]) ajv.addFormat(format, () => true);
  }
  ajv.addSchema(load("spdx.schema.json"), "http://cyclonedx.org/schema/spdx.schema.json");
  ajv.addSchema(load("jsf-0.82.schema.json"), "http://cyclonedx.org/schema/jsf-0.82.schema.json");
  validateBom = ajv.compile(load("bom-1.6.schema.json"));
});

function schemaErrors(doc: unknown): string[] {
  const ok = validateBom(doc);
  if (ok) return [];
  return (validateBom.errors ?? []).map(
    (e) => `${e.instancePath} ${e.keyword} ${e.message}`,
  );
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cyclonedx-conf-"));
  fs.writeFileSync(
    path.join(tmpDir, "package.json"),
    JSON.stringify({
      name: "conformance-fixture",
      version: "1.0.0",
      dependencies: {
        "left-pad": "1.3.0",
      },
    }),
  );
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("CycloneDX 1.6 conformance with external threat intel and two-tier scoring", () => {
  it("serializes EPSS and CVSS into vulnerabilities[].ratings conforming to schema", () => {
    const findings: Finding[] = [
      {
        rule: "CVE_VULNERABILITY",
        severity: "critical",
        category: "vulnerability",
        file: "package.json",
        description: "Known critical vulnerability in dependency",
        cve: "CVE-2024-12345",
        cvss: 9.8,
        epss: 0.854,
        cisaKev: true,
      },
    ];

    const verdict: TwoTierVerdict = {
      tier: 2,
      verdict: "CRITICAL / REJECT",
      tier1Blocked: false,
      exploitabilityScore: 98.0,
      heuristicScore: 25.0,
      governanceScore: 40.0,
      compositeRiskScore: 82.5,
      level: "CRITICAL",
      exitCode: 1,
      vulnerabilitiesEvaluated: 1,
    };

    const doc = generateSbomDocument(tmpDir, findings, [], {
      slsaLevel: 2,
      attackChainFindings: findings,
      twoTierVerdict: verdict,
      compositeRiskScore: 82.5,
    });

    const errors = schemaErrors(doc);
    expect(errors).toEqual([]);

    expect(doc.vulnerabilities).toBeDefined();
    expect(doc.vulnerabilities!.length).toBeGreaterThan(0);

    const vuln = doc.vulnerabilities!.find((v) => v.id === "CVE-2024-12345");
    expect(vuln).toBeDefined();

    // A local finding can carry a numeric score without provenance or a vector.
    expect(vuln!.ratings).toBeDefined();
    expect(vuln!.ratings!).toHaveLength(2);

    const cvssRating = vuln!.ratings!.find((r) => r.source?.name === "supply-chain-guard");
    expect(cvssRating).toBeDefined();
    expect(cvssRating!.score).toBe(9.8);
    expect(cvssRating!.severity).toBe("critical");
    expect(cvssRating!.method).toBe("other");

    const epssRating = vuln!.ratings!.find((r) => r.source?.name === "FIRST");
    expect(epssRating).toBeDefined();
    expect(epssRating!.score).toBe(0.854);
    expect(epssRating!.source?.name).toBe("FIRST");

    // Analysis detail check: CISA KEV
    expect(vuln!.analysis?.detail).toContain("CISA KEV: Known Exploited Vulnerability");
  });

  it("serializes external vulnerability inputs conforming to schema", () => {
    const verdict: TwoTierVerdict = {
      tier: 2,
      verdict: "HIGH / REVIEW_REQUIRED",
      tier1Blocked: false,
      exploitabilityScore: 65.0,
      heuristicScore: 15.0,
      governanceScore: 35.0,
      compositeRiskScore: 61.25,
      level: "HIGH",
      exitCode: 2,
      vulnerabilitiesEvaluated: 1,
    };

    const doc = generateSbomDocument(tmpDir, [], [], {
      slsaLevel: 3,
      twoTierVerdict: verdict,
      compositeRiskScore: 61.25,
      vulnerabilities: [
        {
          id: "CVE-2023-9999",
          cve: "CVE-2023-9999",
          cvss: 7.5,
          epss: 0.12,
          inCisaKev: true,
          cisaKevDateAdded: "2023-11-01",
        },
      ],
    });

    const errors = schemaErrors(doc);
    expect(errors).toEqual([]);

    const vuln = doc.vulnerabilities?.find((v) => v.id === "CVE-2023-9999");
    expect(vuln).toBeDefined();
    expect(vuln?.analysis?.detail).toContain("CISA KEV: Known Exploited Vulnerability");
    expect(vuln?.analysis?.detail).toContain("Added: 2023-11-01");
  });

  it("retains every affected component when one CVE matches multiple packages", () => {
    const doc = generateSbomDocument(tmpDir, [], [], {
      vulnerabilities: [
        {
          id: "GHSA-example-one",
          cve: "CVE-2026-1234",
          cvss: 8.1,
          affectsRef: "pkg:npm/first@1.0.0",
        },
        {
          id: "GHSA-example-two",
          cve: "CVE-2026-1234",
          cvss: 8.1,
          affectsRef: "pkg:npm/second@2.0.0",
        },
      ],
    });

    expect(schemaErrors(doc)).toEqual([]);
    const matches = doc.vulnerabilities?.filter((v) => v.id === "CVE-2026-1234");
    expect(matches).toHaveLength(1);
    expect(matches?.[0].affects).toEqual([
      { ref: "pkg:npm/first@1.0.0" },
      { ref: "pkg:npm/second@2.0.0" },
    ]);
  });

  it("retains distinct ratings when later records for one CVE are more severe", () => {
    const doc = generateSbomDocument(tmpDir, [], [], {
      vulnerabilities: [
        {
          id: "GHSA-low",
          cve: "CVE-2026-7777",
          cvss: 4,
          source: { name: "Source A", url: "https://example.test/a" },
        },
        {
          id: "GHSA-high",
          cve: "CVE-2026-7777",
          cvss: 9.8,
          source: { name: "Source B", url: "https://example.test/b" },
        },
      ],
    });

    expect(schemaErrors(doc)).toEqual([]);
    expect(doc.vulnerabilities?.[0].ratings?.map((rating) => rating.score)).toEqual([4, 9.8]);
  });

  it("retains every affected component for repeated confirmed-malware records", () => {
    const doc = generateSbomDocument(tmpDir, [], [], {
      confirmedMalware: [
        {
          id: "MAL-2026-1",
          packageName: "first",
          ecosystem: "npm",
          source: { name: "OSV" },
          affectsRef: "pkg:npm/first@1.0.0",
        },
        {
          id: "MAL-2026-1",
          packageName: "second",
          ecosystem: "npm",
          source: { name: "OSV" },
          affectsRef: "pkg:npm/second@2.0.0",
        },
      ],
    });

    expect(schemaErrors(doc)).toEqual([]);
    expect(doc.vulnerabilities?.[0].affects).toEqual([
      { ref: "pkg:npm/first@1.0.0" },
      { ref: "pkg:npm/second@2.0.0" },
    ]);
  });

  it("preserves a CVSS v4 vector even when no local v4 calculator supplies a score", () => {
    const vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    const doc = generateSbomDocument(tmpDir, [], [], {
      vulnerabilities: [{
        id: "CVE-2026-4000",
        cve: "CVE-2026-4000",
        cvssVector: vector,
        cvssMethod: "CVSSv4",
        source: { name: "OSV", url: "https://osv.dev/vulnerability/CVE-2026-4000" },
      }],
    });

    expect(schemaErrors(doc)).toEqual([]);
    expect(doc.vulnerabilities?.[0].ratings).toEqual([{
      source: { name: "OSV", url: "https://osv.dev/vulnerability/CVE-2026-4000" },
      method: "CVSSv4",
      vector,
    }]);
  });

  it("annotates SLSA level, attack chains, and composite risk score in properties conforming to schema", () => {
    const attackFindings: Finding[] = [
      {
        rule: "INSTALL_HOOK_EXEC",
        severity: "high",
        category: "install-hook",
        description: "Executes external command on install",
      },
    ];

    const verdict: TwoTierVerdict = {
      tier: 1,
      verdict: "CRITICAL / REJECT",
      tier1Blocked: true,
      tier1Reasons: ["Confirmed malware signature"],
      level: "CRITICAL",
      exitCode: 1,
      vulnerabilitiesEvaluated: 0,
    };

    const doc = generateSbomDocument(tmpDir, attackFindings, [], {
      slsaLevel: 1,
      attackChainFindings: attackFindings,
      twoTierVerdict: verdict,
    });

    const errors = schemaErrors(doc);
    expect(errors).toEqual([]);

    const props = doc.metadata.component?.properties;
    expect(props).toBeDefined();

    const slsaProp = props!.find((p) => p.name === "supply-chain-guard:slsa:level");
    expect(slsaProp?.value).toBe("1");

    const attackChainProp = props!.find((p) => p.name === "supply-chain-guard:attack-chain:findings");
    expect(attackChainProp?.value).toBe("INSTALL_HOOK_EXEC");

    const verdictProp = props!.find((p) => p.name === "supply-chain-guard:risk:verdict");
    expect(verdictProp?.value).toBe("CRITICAL / REJECT");
  });

  it("renders through formatReport(report, 'sbom') producing valid CycloneDX 1.6 output", () => {
    const report: ScanReport = {
      target: tmpDir,
      timestamp: new Date().toISOString(),
      findings: [],
      score: 0,
      riskLevel: "low",
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      sbomDocument: generateSbomDocument(tmpDir, [], [], {
        slsaLevel: 3,
        compositeRiskScore: 10.0,
      }),
      twoTierVerdict: {
        tier: 2,
        verdict: "LOW / PASS",
        tier1Blocked: false,
        compositeRiskScore: 10.0,
        level: "LOW",
        exitCode: 0,
        vulnerabilitiesEvaluated: 0,
      },
    };

    const rawJson = formatReport(report, "sbom");
    const parsed = JSON.parse(rawJson);

    const errors = schemaErrors(parsed);
    expect(errors).toEqual([]);
    expect(parsed.bomFormat).toBe("CycloneDX");
    expect(parsed.specVersion).toBe("1.6");
  });
});
