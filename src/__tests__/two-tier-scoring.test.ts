/**
 * Two-tier gated verdict and risk scoring tests.
 *
 * Verifies Tier 1 binary blocker gate (malware signatures, complete attack chains,
 * C2 endpoints, Discord/Telegram webhooks, Solana drainers) and Tier 2 orthogonal
 * scoring vectors (S_vuln with EPSS and CISA KEV, S_heur with 1.3 correlation scaling,
 * S_hyg with SLSA multipliers and Scorecard fallback, and CRS composite scoring).
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { formatReport } from "../reporter.js";
import {
  evaluateTier1Gate,
  calculateExploitabilityVector,
  calculateHeuristicVector,
  calculateGovernanceVector,
  calculateCompositeRiskScore,
  evaluateTwoTierVerdict,
  getTwoTierExitCode,
} from "../two-tier-scoring.js";
import type { Finding, IncidentCluster, VulnerabilityScoreInput } from "../types.js";

function makeFinding(rule: string, overrides: Partial<Finding> = {}): Finding {
  return {
    rule,
    severity: "high",
    category: "suspicious",
    file: "test.js",
    description: `Finding for rule ${rule}`,
    ...overrides,
  };
}

describe("two-tier scoring engine", () => {
  describe("Tier 1 Threat and Attack-Chain Gate", () => {
    it("blocks on confirmed malware rule (OSV Malicious Database)", () => {
      const findings: Finding[] = [
        makeFinding("OSV_MALICIOUS_PACKAGE", {
          severity: "critical",
          description: "Package flagged in OSV Malicious Database",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.length).toBeGreaterThan(0);
      expect(result.reasons[0]).toContain("OSV_MALICIOUS_PACKAGE");
    });

    it("blocks on GlassWorm campaign indicators", () => {
      const findings: Finding[] = [
        makeFinding("GLASSWORM_STAGE2_DOMAIN", {
          severity: "critical",
          description: "GlassWorm stage 2 payload domain identified",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("GLASSWORM_STAGE2_DOMAIN"))).toBe(true);
    });

    it("blocks on Shai-Hulud worm markers", () => {
      const findings: Finding[] = [
        makeFinding("SHAI_HULUD_WORM", {
          severity: "critical",
          description: "Self-replicating npm worm routine detected",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("SHAI_HULUD_WORM"))).toBe(true);
    });

    it("does NOT block on the malware category alone", () => {
      // `category: "malware"` is a bucket label about 30 rules across 14 scanner
      // modules set, not a confirmed signature. INSTALL_HOOK_OBFUSCATED carries it
      // and fires on any install hook containing `Buffer.from(`, so treating the
      // category as a Tier 1 trigger rejected ordinary packages as confirmed malware.
      const findings: Finding[] = [
        makeFinding("CUSTOM_TROJAN", {
          severity: "critical",
          category: "malware",
          description: "Custom backdoored module",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(false);
    });

    it("does NOT block on an obfuscated install hook alone", () => {
      const findings: Finding[] = [
        makeFinding("INSTALL_HOOK_OBFUSCATED", {
          severity: "high",
          category: "malware",
          description: "postinstall script contains encoding/decoding operations",
        }),
      ];
      expect(evaluateTier1Gate(findings).blocked).toBe(false);
    });

    it("does NOT treat a generic backconnect proxy as confirmed C2", () => {
      const findings: Finding[] = [
        makeFinding("PROXY_BACKCONNECT", {
          severity: "high",
          description: "Connects through an external socks5 proxy",
          match: "socks5://198.51.100.10:1080",
        }),
      ];

      expect(evaluateTier1Gate(findings).blocked).toBe(false);
    });

    it("does NOT block on invisible Unicode alone", () => {
      // The project's own high-but-not-critical fixture is a clean package plus a
      // U+200B string. Zero-width characters are a heuristic, not a signature.
      const findings: Finding[] = [
        makeFinding("INVISIBLE_UNICODE", {
          severity: "high",
          description: "Suspicious invisible Unicode characters detected",
        }),
      ];
      expect(evaluateTier1Gate(findings).blocked).toBe(false);
    });

    it("does NOT complete a three-stage chain from two findings", () => {
      // INSTALL_HOOK_NETWORK used to sit in both the ingress and the exfiltration
      // set, and the npmrc/env-harvest rules in both ingress and access, so two
      // findings covered three stages.
      const findings: Finding[] = [
        makeFinding("INSTALL_HOOK_NETWORK", {
          severity: "medium",
          description: "Install hook makes a network call",
        }),
        makeFinding("SECRETS_NPM_TOKEN", {
          severity: "medium",
          description: "Reads npm auth token",
        }),
      ];
      expect(evaluateTier1Gate(findings).blocked).toBe(false);
    });

    it("blocks on complete attack chain: Ingress + Access + Exfiltration", () => {
      const findings: Finding[] = [
        makeFinding("INSTALL_HOOK_POSTINSTALL", {
          severity: "high",
          description: "Package executes script on install",
          correlationId: "chain-1",
        }),
        makeFinding("SECRETS_NPM_TOKEN", {
          severity: "critical",
          description: "Reads npm auth token",
          correlationId: "chain-1",
        }),
        makeFinding("ENV_EXFILTRATION", {
          severity: "critical",
          description: "Transmits environment secrets to remote host",
          correlationId: "chain-1",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("Complete attack chain detected"))).toBe(true);
    });

    it("does not invent an attack chain across unrelated files", () => {
      const findings = [
        makeFinding("INSTALL_HOOK_POSTINSTALL", { file: "package.json" }),
        makeFinding("SECRETS_NPM_TOKEN", { file: "scripts/read-token.js" }),
        makeFinding("ENV_EXFILTRATION", { file: ".github/workflows/publish.yml" }),
      ];

      expect(evaluateTier1Gate(findings).blocked).toBe(false);
    });

    it("does not treat ordinary Solana mainnet usage as exfiltration", () => {
      expect(evaluateTier1Gate([
        makeFinding("SOLANA_MAINNET", { description: "Uses the public Solana mainnet endpoint" }),
      ]).blocked).toBe(false);
    });

    it("blocks on authoritative confirmed-malware input independently of CVSS", () => {
      const result = evaluateTier1Gate([], [], [{
        id: "MAL-2026-0001",
        packageName: "malicious-fixture",
        packageVersion: "1.0.0",
        ecosystem: "npm:",
        source: { name: "OSV" },
      }]);

      expect(result.blocked).toBe(true);
      expect(result.reasons.join(" ")).toContain("MAL-2026-0001");
    });

    it("does not trigger full attack chain when missing one link", () => {
      const findings: Finding[] = [
        makeFinding("INSTALL_HOOK_POSTINSTALL", {
          severity: "high",
          description: "Package executes script on install",
        }),
        makeFinding("SECRETS_NPM_TOKEN", {
          severity: "critical",
          description: "Reads npm auth token",
        }),
        // No exfiltration rule
      ];
      const result = evaluateTier1Gate(findings);
      // Not blocked by full attack chain
      expect(result.blocked).toBe(false);
    });

    it("blocks on hardcoded C2 infrastructure", () => {
      const findings: Finding[] = [
        makeFinding("IOC_KNOWN_C2_DOMAIN", {
          severity: "critical",
          description: "Command and control server connection",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("Hardcoded C2 infrastructure"))).toBe(true);
    });

    it("blocks on Discord webhook exfiltration endpoint", () => {
      const findings: Finding[] = [
        makeFinding("DISCORD_WEBHOOK_EXFIL", {
          severity: "high",
          description: "Sends payload to Discord webhook",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("Discord/Telegram exfiltration"))).toBe(true);
    });

    it("blocks on regex pattern match for Discord webhook in match property", () => {
      const findings: Finding[] = [
        makeFinding("DYNAMIC_HTTP_POST", {
          severity: "medium",
          match: "https://discord.com/api/webhooks/123456789/abcdef",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("Discord webhook exfiltration URL"))).toBe(true);
    });

    it("blocks on regex pattern match for Telegram Bot API in match property", () => {
      const findings: Finding[] = [
        makeFinding("DYNAMIC_HTTP_POST", {
          severity: "medium",
          match: "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("Telegram Bot exfiltration URL"))).toBe(true);
    });

    it("blocks on malicious Solana program identifier", () => {
      const findings: Finding[] = [
        makeFinding("IOC_KNOWN_C2_WALLET", {
          severity: "critical",
          description: "Solana wallet drainer program invoked",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("Malicious Solana Program"))).toBe(true);
    });

    it("blocks on correlated incident cluster with full kill-chain", () => {
      const incidents: IncidentCluster[] = [
        {
          id: "cluster-1",
          name: "Credential Harvesting Malware Campaign",
          severity: "critical",
          confidence: 0.95,
          indicators: ["INSTALL_HOOK_PREINSTALL", "SECRETS_NPM_TOKEN", "ENV_EXFILTRATION"],
          findings: [
            makeFinding("INSTALL_HOOK_PREINSTALL"),
            makeFinding("SECRETS_NPM_TOKEN"),
            makeFinding("ENV_EXFILTRATION"),
          ],
          narrative: "Preinstall hook steals token and exfiltrates via network",
        },
      ];
      const result = evaluateTier1Gate([], incidents);
      expect(result.blocked).toBe(true);
      expect(result.reasons.some((r) => r.includes("Correlated attack chain incident"))).toBe(true);
    });

    it("passes Tier 1 gate when findings are benign hygiene issues", () => {
      const findings: Finding[] = [
        makeFinding("NETWORK_HTTP_CALL", {
          severity: "low",
          category: "network",
          description: "Plain HTTP request detected",
        }),
        makeFinding("PACKAGE_HAS_NO_LICENSE", {
          severity: "medium",
          category: "governance",
          description: "Missing license field",
        }),
      ];
      const result = evaluateTier1Gate(findings);
      expect(result.blocked).toBe(false);
      expect(result.reasons).toHaveLength(0);
    });
  });

  describe("Tier 2 Exploitability Vector (S_vuln)", () => {
    it("calculates S_vuln with CVSS and EPSS", () => {
      // CVSS = 8.0, EPSS = 0.25 -> 8.0 * 10 * sqrt(0.25) = 80 * 0.5 = 40.0
      const vulns: VulnerabilityScoreInput[] = [
        { id: "CVE-2026-1001", cvss: 8.0, epss: 0.25 },
      ];
      const sVuln = calculateExploitabilityVector(vulns);
      expect(sVuln).toBe(40.0);
    });

    it("forces EPSS to 1.0 when vulnerability is in CISA KEV", () => {
      // CVSS = 7.5, EPSS = 0.05, in CISA KEV -> EPSS becomes 1.0 -> 7.5 * 10 * sqrt(1.0) = 75.0
      const vulns: VulnerabilityScoreInput[] = [
        { id: "CVE-2026-1002", cvss: 7.5, epss: 0.05, inCisaKev: true },
      ];
      const sVuln = calculateExploitabilityVector(vulns);
      expect(sVuln).toBe(75.0);
    });

    it("takes maximum score among multiple vulnerabilities", () => {
      const vulns: VulnerabilityScoreInput[] = [
        { id: "CVE-1", cvss: 6.0, epss: 0.1 }, // 60 * sqrt(0.1) ~ 18.97
        { id: "CVE-2", cvss: 9.0, epss: 0.49 }, // 90 * 0.7 = 63.0
        { id: "CVE-3", cvss: 5.0, epss: 0.16 }, // 50 * 0.4 = 20.0
      ];
      const sVuln = calculateExploitabilityVector(vulns);
      expect(sVuln).toBe(63.0);
    });

    it("returns 0 when vulnerability list is empty", () => {
      expect(calculateExploitabilityVector([])).toBe(0);
    });

    it("caps score at 100 even with extreme input", () => {
      const vulns: VulnerabilityScoreInput[] = [
        { id: "CVE-EXTREME", cvss: 10.0, epss: 1.0 },
      ];
      const sVuln = calculateExploitabilityVector(vulns);
      expect(sVuln).toBe(100.0);
    });

    it("requires review when a KEV advisory has no supported CVSS score", () => {
      const verdict = evaluateTwoTierVerdict([], [], {
        scorecard: 10,
        slsaLevel: 3,
        vulnerabilities: [{
          id: "CVE-2026-4000",
          inCisaKev: true,
          epss: 0.99,
          cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
          cvssMethod: "CVSSv4",
        }],
      });

      expect(verdict.exploitabilityScore).toBe(0);
      expect(verdict.verdict).toBe("HIGH / REVIEW_REQUIRED");
      expect(verdict.exitCode).toBe(1);
    });

    it("requires review when a high-CVSS advisory has no EPSS coverage", () => {
      const verdict = evaluateTwoTierVerdict([], [], {
        scorecard: 10,
        slsaLevel: 3,
        vulnerabilities: [{ id: "CVE-2026-9000", cvss: 9.8 }],
      });

      expect(verdict.exploitabilityScore).toBe(0);
      expect(verdict.verdict).toBe("HIGH / REVIEW_REQUIRED");
      expect(verdict.exitCode).toBe(1);
    });
  });

  describe("Tier 2 Heuristic Vector (S_heur)", () => {
    it("accrues baseline weights: critical 25, high 15, medium 5, low 2, info 0", () => {
      const findings: Finding[] = [
        makeFinding("RULE_CRIT", { severity: "critical" }),
        makeFinding("RULE_HIGH", { severity: "high" }),
        makeFinding("RULE_MED", { severity: "medium" }),
        makeFinding("RULE_LOW", { severity: "low" }),
        makeFinding("RULE_INFO", { severity: "info" }),
      ];
      const { score, correlatedInteraction } = calculateHeuristicVector(findings);
      expect(correlatedInteraction).toBe(false);
      // 25 + 15 + 5 + 2 = 47
      expect(score).toBe(47);
    });

    it("deduplicates multiple findings for the same rule", () => {
      const findings: Finding[] = [
        makeFinding("RULE_MED", { severity: "medium", file: "a.js" }),
        makeFinding("RULE_MED", { severity: "medium", file: "b.js" }),
        makeFinding("RULE_MED", { severity: "medium", file: "c.js" }),
      ];
      const { score } = calculateHeuristicVector(findings);
      // medium weight is 5, counted once
      expect(score).toBe(5);
    });

    it("scales sum by factor 1.3 when correlated indicators interact", () => {
      const findings: Finding[] = [
        makeFinding("RULE_HIGH_1", { severity: "high", correlationId: "corr-1" }),
        makeFinding("RULE_HIGH_2", { severity: "high", correlationId: "corr-1" }),
      ];
      const { score, correlatedInteraction } = calculateHeuristicVector(findings);
      expect(correlatedInteraction).toBe(true);
      // (15 + 15) * 1.3 = 30 * 1.3 = 39.0
      expect(score).toBe(39.0);
    });

    it("scales sum by factor 1.3 when incident clusters exist", () => {
      const findings: Finding[] = [
        makeFinding("RULE_MED_1", { severity: "medium" }),
        makeFinding("RULE_MED_2", { severity: "medium" }),
      ];
      const incidents: IncidentCluster[] = [
        {
          id: "cluster-partial",
          name: "Suspicious co-occurrence",
          severity: "medium",
          confidence: 0.7,
          indicators: ["RULE_MED_1", "RULE_MED_2"],
          files: ["test.js"],
          narrative: "Two indicators observed together",
        },
      ];
      const { score, correlatedInteraction } = calculateHeuristicVector(findings, incidents);
      expect(correlatedInteraction).toBe(true);
      // (5 + 5) * 1.3 = 10 * 1.3 = 13.0
      expect(score).toBe(13.0);
    });

    it("caps S_heur at 100", () => {
      const findings: Finding[] = [];
      for (let i = 0; i < 10; i++) {
        findings.push(makeFinding(`RULE_CRIT_${i}`, { severity: "critical" }));
      }
      const { score } = calculateHeuristicVector(findings);
      expect(score).toBe(100);
    });
  });

  describe("Tier 2 Governance Vector (S_hyg)", () => {
    it("calculates S_hyg with unverified SLSA (M_slsa = 1.0)", () => {
      // Scorecard = 6.0, slsaLevel = 0 -> 10 * (10 - 6.0) * 1.0 = 40.0
      const res = calculateGovernanceVector(6.0, 0);
      expect(res.score).toBe(40.0);
      expect(res.mSlsa).toBe(1.0);
      expect(res.scorecardUsed).toBe(6.0);
    });

    it("applies M_slsa = 0.7 for SLSA L1 / L2", () => {
      // Scorecard = 5.0, slsaLevel = 2 -> 10 * (10 - 5.0) * 0.7 = 50 * 0.7 = 35.0
      const res = calculateGovernanceVector(5.0, 2);
      expect(res.score).toBe(35.0);
      expect(res.mSlsa).toBe(0.7);
    });

    it("applies M_slsa = 0.4 for SLSA L3", () => {
      // Scorecard = 5.0, slsaLevel = 3 -> 10 * (10 - 5.0) * 0.4 = 50 * 0.4 = 20.0
      const res = calculateGovernanceVector(5.0, 3);
      expect(res.score).toBe(20.0);
      expect(res.mSlsa).toBe(0.4);
    });

    it("falls back to Scorecard 3.0 when undefined or invalid", () => {
      // Fallback 3.0, slsaLevel = 0 -> 10 * (10 - 3.0) * 1.0 = 70.0
      const res = calculateGovernanceVector(undefined, 0);
      expect(res.score).toBe(70.0);
      expect(res.scorecardUsed).toBe(3.0);
      expect(res.mSlsa).toBe(1.0);
    });
  });

  describe("Composite Risk Score (CRS)", () => {
    it("computes CRS = min(100, 0.35 * S_vuln + 0.45 * S_heur + 0.20 * S_hyg)", () => {
      // S_vuln = 50, S_heur = 40, S_hyg = 30
      // CRS = 0.35 * 50 + 0.45 * 40 + 0.20 * 30 = 17.5 + 18.0 + 6.0 = 41.5
      const crs = calculateCompositeRiskScore(50, 40, 30);
      expect(crs).toBe(41.5);
    });

    it("caps CRS at 100", () => {
      const crs = calculateCompositeRiskScore(100, 100, 100);
      expect(crs).toBe(100);
    });
  });

  describe("Complete evaluateTwoTierVerdict and exit codes", () => {
    it("skips formula calculation and returns CRITICAL / REJECT on Tier 1 hit", () => {
      const findings: Finding[] = [
        makeFinding("OSV_MALICIOUS_PACKAGE", { severity: "critical" }),
      ];
      const verdict = evaluateTwoTierVerdict(findings, [], {
        scorecard: 9.0,
        slsaLevel: 3,
        vulnerabilities: [{ id: "CVE-1", cvss: 9.0, epss: 0.8 }],
      });

      expect(verdict.tier).toBe(1);
      expect(verdict.tier1Blocked).toBe(true);
      expect(verdict.verdict).toBe("CRITICAL / REJECT");
      expect(verdict.level).toBe("CRITICAL");
      expect(verdict.exitCode).toBe(2);
      expect(getTwoTierExitCode(verdict)).toBe(2);
      // Formula scores must not be calculated
      expect(verdict.compositeRiskScore).toBeUndefined();
      expect(verdict.exploitabilityScore).toBeUndefined();
    });

    it("evaluates Tier 2 CRITICAL (CRS >= 80) -> Exit Code 2", () => {
      // Force high S_vuln = 100, high S_heur = 80, S_hyg = 70
      // CRS = 0.35 * 100 + 0.45 * 80 + 0.20 * 70 = 35 + 36 + 14 = 85
      const findings: Finding[] = [
        makeFinding("HIGH_SUSP_1", { severity: "critical" }),
        makeFinding("HIGH_SUSP_2", { severity: "critical" }),
        makeFinding("HIGH_SUSP_3", { severity: "critical" }),
        makeFinding("HIGH_SUSP_4", { severity: "high" }),
      ];
      const vulns: VulnerabilityScoreInput[] = [
        { id: "CVE-KEV", cvss: 10.0, inCisaKev: true },
      ];
      const verdict = evaluateTwoTierVerdict(findings, [], {
        scorecard: 3.0,
        slsaLevel: 0,
        vulnerabilities: vulns,
      });

      expect(verdict.tier).toBe(2);
      expect(verdict.tier1Blocked).toBe(false);
      expect(verdict.compositeRiskScore).toBeGreaterThanOrEqual(80);
      expect(verdict.level).toBe("CRITICAL");
      expect(verdict.verdict).toBe("CRITICAL / REJECT");
      expect(verdict.exitCode).toBe(2);
      expect(getTwoTierExitCode(verdict)).toBe(2);
    });

    it("evaluates Tier 2 HIGH (CRS 55 to 79) -> Exit Code 1", () => {
      // S_vuln = 60 (0.35 * 60 = 21)
      // S_heur = 50 (0.45 * 50 = 22.5)
      // S_hyg = 70 (0.20 * 70 = 14)
      // CRS = 21 + 22.5 + 14 = 57.5
      const findings: Finding[] = [
        makeFinding("SUSP_1", { severity: "critical" }),
        makeFinding("SUSP_2", { severity: "high" }),
        makeFinding("SUSP_3", { severity: "medium" }),
        makeFinding("SUSP_4", { severity: "low" }),
        makeFinding("SUSP_5", { severity: "low" }),
      ];
      const vulns: VulnerabilityScoreInput[] = [
        { id: "CVE-HIGH", cvss: 6.0, epss: 1.0 },
      ];
      const verdict = evaluateTwoTierVerdict(findings, [], {
        scorecard: 3.0,
        slsaLevel: 0,
        vulnerabilities: vulns,
      });

      expect(verdict.tier).toBe(2);
      expect(verdict.tier1Blocked).toBe(false);
      expect(verdict.compositeRiskScore).toBeGreaterThanOrEqual(55);
      expect(verdict.compositeRiskScore).toBeLessThan(80);
      expect(verdict.compositeRiskLevel).toBe("HIGH");
      expect(verdict.level).toBe("CRITICAL");
      expect(verdict.verdict).toBe("CRITICAL / REJECT");
      // HIGH maps to 1, but SUSP_1 is a critical finding and the severity floor
      // keeps the code at least as strong as the default gate would give.
      expect(verdict.exitCode).toBe(2);
      expect(getTwoTierExitCode(verdict)).toBe(2);
    });

    it("floors the exit code at the default severity gate", () => {
      // Without external vulnerability inputs S_vuln is 0, so CRS cannot reach the
      // 80 CRITICAL threshold: three criticals plus a high score 54.5 (MEDIUM).
      // The default gate exits 2 on that report, so --two-tier must not exit 0.
      const findings: Finding[] = [
        makeFinding("SUSP_A", { severity: "critical" }),
        makeFinding("SUSP_B", { severity: "critical" }),
        makeFinding("SUSP_C", { severity: "critical" }),
        makeFinding("SUSP_D", { severity: "high" }),
      ];
      const verdict = evaluateTwoTierVerdict(findings, []);

      expect(verdict.tier1Blocked).toBe(false);
      expect(verdict.compositeRiskLevel).toBe("MEDIUM");
      expect(verdict.level).toBe("CRITICAL");
      expect(verdict.verdict).toBe("CRITICAL / REJECT");
      expect(verdict.compositeRiskScore).toBeLessThan(55);
      expect(verdict.exitCode).toBe(2);
    });

    it("maps a Tier 2 CRITICAL with no critical findings to exit code 2", () => {
      // Pins the mapping itself. The floor tests above cannot: their findings are
      // critical, so the floor would produce 2 even if CRITICAL mapped to 1.
      // 12 distinct medium findings -> S_heur 60; cvss 10 at epss 1.0 -> S_vuln 100;
      // scorecard 0 -> S_hyg 100. CRS = 35 + 27 + 20 = 82.
      const findings: Finding[] = Array.from({ length: 12 }, (_, i) =>
        makeFinding(`MED_RULE_${i}`, { severity: "medium" }),
      );
      const verdict = evaluateTwoTierVerdict(findings, [], {
        scorecard: 0,
        slsaLevel: 0,
        vulnerabilities: [{ id: "CVE-X", cvss: 10.0, epss: 1.0 }],
      });

      expect(verdict.level).toBe("CRITICAL");
      expect(verdict.compositeRiskScore).toBeGreaterThanOrEqual(80);
      // 2 is critical and 1 is high, the same contract getReportExitCode uses.
      expect(verdict.exitCode).toBe(2);
    });

    it("maps a Tier 2 HIGH with no high findings to exit code 1", () => {
      // No findings at all, so the severity floor is 0 and only the mapping decides.
      // S_vuln 100, S_heur 0, S_hyg 100 -> CRS = 35 + 20 = 55.
      const verdict = evaluateTwoTierVerdict([], [], {
        scorecard: 0,
        slsaLevel: 0,
        vulnerabilities: [{ id: "CVE-Y", cvss: 10.0, epss: 1.0 }],
      });

      expect(verdict.level).toBe("HIGH");
      expect(verdict.exitCode).toBe(1);
    });

    it("floors a high-only report at exit code 1", () => {
      const verdict = evaluateTwoTierVerdict(
        [makeFinding("SUSP_H", { severity: "high" })],
        [],
        { scorecard: 9.5, slsaLevel: 3 },
      );

      expect(verdict.compositeRiskLevel).toBe("LOW");
      expect(verdict.level).toBe("HIGH");
      expect(verdict.verdict).toBe("HIGH / REVIEW_REQUIRED");
      expect(verdict.exitCode).toBe(1);
    });

    it("keeps score-excluded governance findings in the enforcement floor", () => {
      const verdict = evaluateTwoTierVerdict([
        makeFinding("RISK_STAGNATION_HIGH", { severity: "high" }),
      ]);

      expect(verdict.compositeRiskLevel).toBe("LOW");
      expect(verdict.level).toBe("HIGH");
      expect(verdict.exitCode).toBe(1);
    });

    it("requires review when requested intelligence coverage is partial", () => {
      const verdict = evaluateTwoTierVerdict([], [], { partialScan: true, scorecard: 10 });

      expect(verdict.compositeRiskLevel).toBe("LOW");
      expect(verdict.verdict).toBe("HIGH / REVIEW_REQUIRED");
      expect(verdict.exitCode).toBe(1);
    });

    it("evaluates Tier 2 MEDIUM (CRS 30 to 54) -> Exit Code 0", () => {
      // Moderate findings and governance
      const findings: Finding[] = [
        makeFinding("MED_1", { severity: "medium" }),
        makeFinding("MED_2", { severity: "medium" }),
      ];
      const vulns: VulnerabilityScoreInput[] = [
        { id: "CVE-MED", cvss: 7.0, epss: 0.49 }, // 70 * 0.7 = 49 -> 0.35 * 49 = 17.15
      ];
      const verdict = evaluateTwoTierVerdict(findings, [], {
        scorecard: 3.0,
        slsaLevel: 0,
        vulnerabilities: vulns,
      });

      expect(verdict.tier).toBe(2);
      expect(verdict.tier1Blocked).toBe(false);
      expect(verdict.compositeRiskScore).toBeGreaterThanOrEqual(30);
      expect(verdict.compositeRiskScore).toBeLessThan(55);
      expect(verdict.level).toBe("MEDIUM");
      expect(verdict.verdict).toBe("MEDIUM / AUDIT_WARNING");
      expect(verdict.exitCode).toBe(0);
      expect(getTwoTierExitCode(verdict)).toBe(0);
    });

    it("evaluates Tier 2 LOW (CRS 0 to 29) -> Exit Code 0", () => {
      // Clean project, high scorecard, SLSA L3
      const verdict = evaluateTwoTierVerdict([], [], {
        scorecard: 9.5,
        slsaLevel: 3,
      });

      expect(verdict.tier).toBe(2);
      expect(verdict.tier1Blocked).toBe(false);
      expect(verdict.compositeRiskScore).toBeLessThan(30);
      expect(verdict.level).toBe("LOW");
      expect(verdict.verdict).toBe("LOW / PASS");
      expect(verdict.exitCode).toBe(0);
      expect(getTwoTierExitCode(verdict)).toBe(0);
    });
  });
});

describe("two-tier is opt-in on the scan path", () => {
  function cleanFixture(label: string): string {
    const wd = fs.mkdtempSync(path.join(os.tmpdir(), "scg-two-tier-"));
    const dir = path.join(wd, label);
    fs.cpSync(path.join(__dirname, "fixtures", "clean-npm-pkg"), dir, { recursive: true });
    return dir;
  }

  it("adds no verdict, no score and no report rows without the flag", async () => {
    // An unconditional verdict changed default text and JSON output for every
    // existing consumer, and attached a composite risk score built on a Scorecard
    // fallback that stands for a FAILED lookup when no lookup had been attempted.
    const report = await scan({ target: cleanFixture("off"), noHistory: true });

    expect(report.twoTierVerdict).toBeUndefined();
    expect(report.compositeRiskScore).toBeUndefined();

    const parsed = JSON.parse(formatReport(report, "json")) as Record<string, unknown>;
    expect(parsed.twoTierVerdict).toBeUndefined();
    expect(parsed.compositeRiskScore).toBeUndefined();
    expect(formatReport(report, "text")).not.toContain("Two-Tier Verdict");
    expect(formatReport(report, "text")).not.toContain("Composite Risk");
  });

  it("adds the verdict when the flag is set", async () => {
    const report = await scan({ target: cleanFixture("on"), noHistory: true, twoTier: true });

    expect(report.twoTierVerdict).toBeDefined();
    expect(report.twoTierVerdict?.verdict).toBe("LOW / PASS");
    expect(formatReport(report, "text")).toContain("Two-Tier Verdict");
  });
});
