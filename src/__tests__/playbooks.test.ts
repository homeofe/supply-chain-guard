import { describe, it, expect } from "vitest";
import { generatePlaybooks } from "../playbooks.js";
import type { IncidentCluster } from "../types.js";

function makeIncident(name: string): IncidentCluster {
  return {
    id: "test-1",
    name,
    severity: "critical",
    confidence: 0.95,
    findings: [],
    narrative: "Test narrative",
    indicators: ["RULE_1"],
  };
}

describe("Playbooks", () => {
  it("should generate playbook for GlassWorm campaign", () => {
    const playbooks = generatePlaybooks([makeIncident("GlassWorm Campaign")]);
    expect(playbooks).toHaveLength(1);
    expect(playbooks[0].immediateActions.length).toBeGreaterThan(0);
    expect(playbooks[0].investigationSteps.length).toBeGreaterThan(0);
    expect(playbooks[0].remediationSteps.length).toBeGreaterThan(0);
    expect(playbooks[0].preventionMeasures.length).toBeGreaterThan(0);
  });

  it("should generate playbook for Claude Code campaign", () => {
    const playbooks = generatePlaybooks([makeIncident("Claude Code Leak Campaign (Vidar/GhostSocks)")]);
    expect(playbooks).toHaveLength(1);
    expect(playbooks[0].summary).toContain("Vidar");
  });

  it("should generate playbook for npm account takeover", () => {
    const playbooks = generatePlaybooks([makeIncident("npm Account Takeover")]);
    expect(playbooks).toHaveLength(1);
    expect(playbooks[0].immediateActions.some((a) => a.includes("pin") || a.includes("ignore-scripts"))).toBe(true);
  });

  it("should generate playbook for fake repo", () => {
    const playbooks = generatePlaybooks([makeIncident("Fake Repository Malware Distribution")]);
    expect(playbooks).toHaveLength(1);
  });

  it("should generate playbook for CI/CD poisoning", () => {
    const playbooks = generatePlaybooks([makeIncident("CI/CD Pipeline Poisoning")]);
    expect(playbooks).toHaveLength(1);
    expect(playbooks[0].remediationSteps.some((s) => s.includes("SHA") || s.includes("Pin"))).toBe(true);
  });

  it("should return empty for unknown incidents", () => {
    const playbooks = generatePlaybooks([makeIncident("Unknown Incident Type")]);
    expect(playbooks).toHaveLength(0);
  });

  it("should handle multiple incidents", () => {
    const playbooks = generatePlaybooks([
      makeIncident("GlassWorm Campaign"),
      makeIncident("npm Account Takeover"),
    ]);
    expect(playbooks).toHaveLength(2);
  });
});
