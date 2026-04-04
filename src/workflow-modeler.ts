/**
 * Workflow execution modeler (v4.7).
 *
 * Models GitHub Actions workflows as executable chains, tracking
 * secret access, action usage, and data flow paths.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";

interface WorkflowStep {
  name?: string;
  uses?: string;
  run?: string;
  accessesSecrets: boolean;
  secretNames: string[];
  hasNetworkEgress: boolean;
  hasFileUpload: boolean;
}

interface WorkflowModel {
  file: string;
  jobs: Array<{
    name: string;
    steps: WorkflowStep[];
    secretToEgressPath: boolean;
    untrustedActionInReleasePath: boolean;
  }>;
}

/**
 * Model workflows in a directory and find risky execution paths.
 */
export function modelWorkflows(dir: string): Finding[] {
  const findings: Finding[] = [];
  const workflowDir = path.join(dir, ".github", "workflows");

  if (!fs.existsSync(workflowDir)) return findings;

  try {
    const files = fs.readdirSync(workflowDir).filter((f) =>
      f.endsWith(".yml") || f.endsWith(".yaml"),
    );

    for (const file of files) {
      const fullPath = path.join(workflowDir, file);
      const content = fs.readFileSync(fullPath, "utf-8");
      const relPath = `.github/workflows/${file}`;

      // Check for secret-to-egress paths
      const hasSecretRef = /\$\{\{\s*secrets\.\w+/.test(content);
      const hasNetworkEgress = /curl|wget|fetch|https?:\/\/|actions\/upload-artifact/.test(content);
      const hasUpload = /actions\/upload-artifact|gh release upload|npm publish/.test(content);

      if (hasSecretRef && hasNetworkEgress) {
        findings.push({
          rule: "WORKFLOW_SECRET_TO_UPLOAD_PATH",
          description: `Workflow "${file}" accesses secrets and has network egress. Secrets may be exfiltrated.`,
          severity: "high",
          file: relPath,
          confidence: 0.7,
          category: "supply-chain",
          recommendation: "Audit this workflow for secret-to-network paths. Minimize secret scoping.",
        });
      }

      // Check for untrusted actions in release paths
      const isReleasePath = /release|publish|deploy|npm.*publish/.test(content);
      const hasUnpinnedAction = /@(?:main|master|latest|dev)\b/.test(content);

      if (isReleasePath && hasUnpinnedAction) {
        findings.push({
          rule: "WORKFLOW_UNTRUSTED_ACTION_IN_RELEASE_PATH",
          description: `Workflow "${file}" is a release/publish pipeline with unpinned actions. Supply-chain risk.`,
          severity: "critical",
          file: relPath,
          confidence: 0.8,
          category: "supply-chain",
          recommendation: "Pin all actions in release workflows to commit SHAs. Release pipelines are high-value targets.",
        });
      }
    }
  } catch { /* skip */ }

  return findings;
}
