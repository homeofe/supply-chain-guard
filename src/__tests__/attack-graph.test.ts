import { describe, it, expect } from "vitest";
import { buildAttackGraph, exportGraphMermaid } from "../attack-graph.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" = "high", file?: string): Finding {
  return { rule, description: `${rule} finding`, severity, file, recommendation: "fix" };
}

describe("Attack Graph", () => {
  it("should build graph from findings", () => {
    const graph = buildAttackGraph([
      makeFinding("EVAL_ATOB", "critical", "src/index.js"),
      makeFinding("ENV_EXFILTRATION", "high", "src/index.js"),
    ], "./project");
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.edges.length).toBeGreaterThan(0);
    expect(graph.nodes.some((n) => n.type === "repo")).toBe(true);
  });

  it("should create IOC nodes for threat intel matches", () => {
    const graph = buildAttackGraph([
      makeFinding("IOC_KNOWN_C2_DOMAIN", "critical", "config.js"),
      makeFinding("DEAD_DROP_TELEGRAM", "critical", "resolver.js"),
    ], "./malware");
    expect(graph.nodes.some((n) => n.type === "ioc")).toBe(true);
  });

  it("should create secret nodes", () => {
    const graph = buildAttackGraph([
      makeFinding("SECRETS_AWS_KEY", "critical", "env.js"),
      makeFinding("INSTALL_HOOK_ENV_HARVEST", "critical", "package.json"),
    ], "./pkg");
    expect(graph.nodes.some((n) => n.type === "secret")).toBe(true);
  });

  it("should identify secret-to-egress attack path", () => {
    const graph = buildAttackGraph([
      makeFinding("SECRETS_AWS_KEY", "critical", "src/index.js"),
      makeFinding("ENV_EXFILTRATION", "high", "src/exfil.js"),
    ], "./compromised");
    expect(graph.paths.some((p) => p.id === "path-secret-to-egress")).toBe(true);
    expect(graph.paths[0]?.severity).toBe("critical");
  });

  it("should identify repo-to-payload path", () => {
    const graph = buildAttackGraph([
      makeFinding("README_LURE_CRACK", "critical", "README.md"),
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
    ], "./fake-repo");
    expect(graph.paths.some((p) => p.id === "path-repo-to-payload")).toBe(true);
  });

  it("should identify install hook backdoor path", () => {
    const graph = buildAttackGraph([
      makeFinding("INSTALL_HOOK_DOWNLOAD_EXEC", "critical", "package.json"),
      makeFinding("INSTALL_HOOK_ENV_HARVEST", "critical", "package.json"),
    ], "./pkg");
    expect(graph.paths.some((p) => p.id === "path-install-hook-backdoor")).toBe(true);
  });

  it("should return empty paths for clean findings", () => {
    const graph = buildAttackGraph([
      makeFinding("HEX_ARRAY", "medium" as "high", "data.js"),
    ], "./clean");
    expect(graph.paths).toHaveLength(0);
  });

  it("should export as Mermaid diagram", () => {
    const graph = buildAttackGraph([
      makeFinding("EVAL_ATOB", "critical", "src/index.js"),
    ], "./project");
    const mermaid = exportGraphMermaid(graph);
    expect(mermaid).toContain("graph TD");
    expect(mermaid.length).toBeGreaterThan(20);
  });
});
