/**
 * Attack graph engine (v4.7).
 *
 * Builds a directed graph of relationships between repos, packages,
 * workflows, secrets, and IOCs. Identifies exploitable attack paths
 * from entry points to impact.
 */

import type {
  Finding, AttackGraph, GraphNode, GraphEdge, AttackPath, Severity,
} from "./types.js";

/**
 * Build an attack graph from scan findings.
 */
export function buildAttackGraph(
  findings: Finding[],
  target: string,
): AttackGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const nodeMap = new Map<string, GraphNode>();

  // Root node
  addNode(nodeMap, nodes, "target", "repo", target);

  // Build nodes and edges from findings
  for (const f of findings) {
    // File nodes
    if (f.file) {
      const fileId = `file:${f.file}`;
      addNode(nodeMap, nodes, fileId, "artifact", f.file, [f.rule]);
      edges.push({ source: "target", target: fileId, type: "depends_on" });
    }

    // IOC nodes
    if (f.rule.startsWith("IOC_") || f.rule.startsWith("THREAT_INTEL") || f.rule.startsWith("DEAD_DROP_")) {
      const iocId = `ioc:${f.rule}`;
      addNode(nodeMap, nodes, iocId, "ioc", f.description.substring(0, 60), [f.rule]);
      if (f.file) edges.push({ source: `file:${f.file}`, target: iocId, type: "references", risk: 10 });
    }

    // Secret nodes
    if (f.rule.startsWith("SECRETS_") || f.rule.startsWith("INSTALL_HOOK_ENV") || f.rule.startsWith("INSTALL_HOOK_NPMRC")) {
      const secretId = `secret:${f.rule}`;
      addNode(nodeMap, nodes, secretId, "secret", f.rule, [f.rule]);
      if (f.file) edges.push({ source: `file:${f.file}`, target: secretId, type: "exfiltrates", risk: 10 });
    }

    // Network/C2 edges
    if (f.rule.includes("EXFILTRATION") || f.rule.includes("NETWORK") || f.rule.includes("C2_")) {
      const c2Id = `ioc:c2-${f.rule}`;
      addNode(nodeMap, nodes, c2Id, "ioc", "C2/Exfil endpoint", [f.rule]);
      if (f.file) edges.push({ source: `file:${f.file}`, target: c2Id, type: "exfiltrates", risk: 10 });
    }

    // Workflow nodes
    if (f.rule.startsWith("GHA_")) {
      const wfId = `workflow:${f.file ?? "unknown"}`;
      addNode(nodeMap, nodes, wfId, "workflow", f.file ?? "GitHub Actions", [f.rule]);
      edges.push({ source: "target", target: wfId, type: "executes" });
    }

    // Install script nodes
    if (f.rule.startsWith("INSTALL_HOOK_") || f.rule.startsWith("SCRIPT_")) {
      const scriptId = `script:install-${f.file ?? "pkg"}`;
      addNode(nodeMap, nodes, scriptId, "script", "Install script", [f.rule]);
      if (f.file) edges.push({ source: `file:${f.file}`, target: scriptId, type: "executes", risk: 8 });
    }
  }

  // Identify attack paths
  const paths = identifyAttackPaths(nodes, edges, findings);

  return { nodes, edges, paths };
}

/**
 * Identify exploitable attack paths in the graph.
 */
function identifyAttackPaths(
  nodes: GraphNode[],
  edges: GraphEdge[],
  findings: Finding[],
): AttackPath[] {
  const paths: AttackPath[] = [];
  const rules = new Set(findings.map((f) => f.rule));

  // Path: Secret access -> Network exfiltration
  if (
    (rules.has("SECRETS_AWS_KEY") || rules.has("SECRETS_GITHUB_TOKEN") || rules.has("INSTALL_HOOK_ENV_HARVEST")) &&
    (rules.has("ENV_EXFILTRATION") || rules.has("INSTALL_HOOK_NETWORK") || rules.has("DEAD_DROP_TELEGRAM"))
  ) {
    paths.push({
      id: "path-secret-to-egress",
      description: "Secret access leads to network exfiltration. Credentials may be stolen.",
      severity: "critical",
      confidence: 0.9,
      nodeIds: findPathNodes(nodes, ["secret", "ioc"]),
    });
  }

  // Path: Repository -> Release -> Executable payload
  if (
    (rules.has("README_LURE_CRACK") || rules.has("CAMPAIGN_CLAUDE_LURE")) &&
    (rules.has("RELEASE_EXE_ARTIFACT") || rules.has("RELEASE_7Z_ARCHIVE"))
  ) {
    paths.push({
      id: "path-repo-to-payload",
      description: "Fake repository lures users into downloading executable malware from releases.",
      severity: "critical",
      confidence: 0.95,
      nodeIds: findPathNodes(nodes, ["repo", "artifact"]),
    });
  }

  // Path: Workflow -> Secret -> External endpoint
  if (
    rules.has("GHA_SECRET_CURL") &&
    (rules.has("GHA_UNPINNED_ACTION") || rules.has("GHA_BASE64_EXEC"))
  ) {
    paths.push({
      id: "path-workflow-secret-egress",
      description: "CI workflow accesses secrets and sends them to external endpoints.",
      severity: "critical",
      confidence: 0.85,
      nodeIds: findPathNodes(nodes, ["workflow", "secret", "ioc"]),
    });
  }

  // Path: Install hook -> Secret harvest -> C2
  if (
    (rules.has("INSTALL_HOOK_DOWNLOAD_EXEC") || rules.has("INSTALL_HOOK_NETWORK")) &&
    (rules.has("INSTALL_HOOK_ENV_HARVEST") || rules.has("INSTALL_HOOK_NPMRC_READ"))
  ) {
    paths.push({
      id: "path-install-hook-backdoor",
      description: "Install script downloads payload, harvests secrets, and contacts C2 infrastructure.",
      severity: "critical",
      confidence: 0.9,
      nodeIds: findPathNodes(nodes, ["script", "secret"]),
    });
  }

  return paths;
}

function addNode(
  map: Map<string, GraphNode>,
  nodes: GraphNode[],
  id: string,
  type: GraphNode["type"],
  label: string,
  findingRules?: string[],
): void {
  if (map.has(id)) {
    const existing = map.get(id)!;
    if (findingRules) {
      existing.findings = [...(existing.findings ?? []), ...findingRules];
    }
    return;
  }
  const node: GraphNode = { id, type, label, findings: findingRules };
  map.set(id, node);
  nodes.push(node);
}

function findPathNodes(nodes: GraphNode[], types: string[]): string[] {
  return nodes.filter((n) => types.includes(n.type)).map((n) => n.id);
}

/**
 * Export attack graph as Mermaid diagram.
 */
export function exportGraphMermaid(graph: AttackGraph): string {
  const lines = ["graph TD"];

  for (const node of graph.nodes) {
    const shape = node.type === "ioc" ? `((${node.label}))` :
                  node.type === "secret" ? `{${node.label}}` :
                  `[${node.label}]`;
    lines.push(`  ${sanitizeId(node.id)}${shape}`);
  }

  for (const edge of graph.edges) {
    const label = edge.label ? `|${edge.label}|` : "";
    const arrow = edge.type === "exfiltrates" ? "==>" : "-->";
    lines.push(`  ${sanitizeId(edge.source)} ${arrow}${label} ${sanitizeId(edge.target)}`);
  }

  // Highlight attack paths
  if (graph.paths.length > 0) {
    lines.push("");
    for (const path of graph.paths) {
      lines.push(`  %% Attack Path: ${path.description}`);
    }
  }

  return lines.join("\n");
}

function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, "_");
}
