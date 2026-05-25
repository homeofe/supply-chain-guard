/**
 * SLSA Provenance Verifier
 *
 * Evaluates a project's SLSA (Supply-chain Levels for Software Artifacts) level
 * based on build configuration, GitHub Actions workflows, and attestation files.
 *
 * Levels:
 *   0 — No evidence of any build process
 *   1 — Build script present (Dockerfile, CI workflow)
 *   2 — Signed build or slsa-github-generator action used
 *   3 — Hermetic build + provenance attestation file present
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";

/** Workflow patterns that indicate SLSA Level 2 (signed/generated provenance) */
const SLSA_LEVEL2_PATTERNS = [
  /slsa-framework\/slsa-github-generator/i,
  /sigstore\/cosign-action/i,
  /sigstore\/gh-action-sigstore-python/i,
  /actions\/attest-build-provenance/i,
  /github\/attest/i,
  // npm publish --provenance generates SLSA provenance via OIDC and uploads to
  // sigstore's public transparency log. Standard path since npm 9, mandatory
  // for Trusted Publishing setups since npm 11.5. Recognise it as Level 2.
  // v5.2.20.
  /npm\s+publish[^\n]*--provenance/i,
];

/** Workflow patterns that indicate SLSA Level 3 (hermetic build) */
const SLSA_LEVEL3_PATTERNS = [
  /slsa-framework\/slsa-github-generator.*@[0-9a-f]{40}/i,
  /uses:\s+slsa-framework\/slsa-github-generator/i,
];

/**
 * Modern canonical SLSA Level 3 path for npm packages.
 *
 * `npm publish --provenance` (npm >= 9.5, mandatory under npm Trusted Publishing
 * since 11.5) generates a Sigstore-signed provenance statement using the GitHub
 * Actions OIDC identity, publishes it to the npm registry, and records it in
 * the public Rekor transparency log. The result is cryptographically
 * non-falsifiable provenance bound to the workflow identity and a specific
 * source commit - the same L3 guarantees the slsa-github-generator reusable
 * workflow produces, just specialised for the npm ecosystem.
 *
 * Requires both signals in the same workflow corpus:
 *   - `npm publish ... --provenance` flag (the publish step itself)
 *   - `id-token: write` permission (OIDC required for Sigstore signing)
 *
 * Without `id-token: write` the publish would fail at runtime, so the check is
 * defence-in-depth: it ensures the workflow could actually mint provenance, not
 * just that someone typed the flag into a non-functional config.
 *
 * v5.2.26: added so projects following the npm-native path (e.g. our own ci.yml)
 * are recognised at the level they actually achieve, instead of being parked at
 * L2 because they don't import the slsa-github-generator reusable workflow.
 */
const NPM_PROVENANCE_PATTERN = /npm\s+publish[^\n]*--provenance/i;
const OIDC_TOKEN_WRITE_PATTERN = /id-token:\s*write/i;

/** Attestation file names that indicate provenance is present */
const ATTESTATION_FILES = [
  "provenance.json",
  "attestation.json",
  "provenance.intoto.jsonl",
  ".sigstore",
  "cosign.pub",
];

/** Known hermetic build indicators in workflow content */
const HERMETIC_BUILD_PATTERNS = [
  /reusable_workflow/i,
  /workflow_call/i,
];

/**
 * Check if a directory contains any GitHub Actions workflow files.
 */
function hasWorkflowFiles(dir: string): string[] {
  const workflowDir = path.join(dir, ".github", "workflows");
  if (!fs.existsSync(workflowDir)) return [];

  try {
    return fs
      .readdirSync(workflowDir)
      .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
      .map((f) => path.join(workflowDir, f));
  } catch {
    return [];
  }
}

/**
 * Read all workflow file contents.
 */
function readWorkflows(workflowFiles: string[]): string {
  return workflowFiles
    .map((f) => {
      try {
        return fs.readFileSync(f, "utf-8");
      } catch {
        return "";
      }
    })
    .join("\n");
}

/**
 * Check if the project root or dist directory contains attestation files.
 */
function hasAttestationFile(dir: string): boolean {
  for (const filename of ATTESTATION_FILES) {
    if (fs.existsSync(path.join(dir, filename))) return true;
    if (fs.existsSync(path.join(dir, "dist", filename))) return true;
    if (fs.existsSync(path.join(dir, ".github", filename))) return true;
  }
  return false;
}

/**
 * Check for a build script (Dockerfile, CI workflow, Makefile, etc.)
 */
function hasBuildScript(dir: string): boolean {
  const buildFiles = [
    "Dockerfile",
    "Makefile",
    "build.sh",
    "build.gradle",
    "pom.xml",
    "CMakeLists.txt",
  ];
  for (const f of buildFiles) {
    if (fs.existsSync(path.join(dir, f))) return true;
  }
  return false;
}

/**
 * Determine SLSA level (0–3) for a project directory.
 *
 * @returns Numeric level 0-3
 */
export function getSLSALevel(dir: string): number {
  const workflowFiles = hasWorkflowFiles(dir);
  const hasWorkflow = workflowFiles.length > 0;
  const buildScript = hasBuildScript(dir);

  // Level 0: no build evidence at all
  if (!hasWorkflow && !buildScript) return 0;

  // Level 1: build script or workflow exists
  if (!hasWorkflow) return 1;

  const allWorkflowContent = readWorkflows(workflowFiles);

  // Level 3: hermetic reusable workflow + attestation file
  const hasHermeticPattern = SLSA_LEVEL3_PATTERNS.some((p) =>
    p.test(allWorkflowContent),
  );
  const hasHermeticBuild = HERMETIC_BUILD_PATTERNS.some((p) =>
    p.test(allWorkflowContent),
  );
  const attestation = hasAttestationFile(dir);

  if (hasHermeticPattern && (hasHermeticBuild || attestation)) return 3;

  // Level 3 (npm-native path): `npm publish --provenance` + OIDC permission.
  // Sigstore-signed, Rekor-logged provenance bound to the workflow identity
  // is non-falsifiable and service-generated - the same security substance
  // as the slsa-github-generator path, just specialised for npm artifacts.
  const hasNpmProvenance = NPM_PROVENANCE_PATTERN.test(allWorkflowContent);
  const hasOidcTokenWrite = OIDC_TOKEN_WRITE_PATTERN.test(allWorkflowContent);
  if (hasNpmProvenance && hasOidcTokenWrite) return 3;

  // Level 2: signed provenance action or cosign
  const hasLevel2 = SLSA_LEVEL2_PATTERNS.some((p) =>
    p.test(allWorkflowContent),
  );
  if (hasLevel2) return 2;

  // Level 1: just has a workflow
  return 1;
}

/**
 * Verify SLSA posture of a project directory and return findings for gaps.
 */
export function verifySLSA(dir: string): Finding[] {
  const findings: Finding[] = [];
  const level = getSLSALevel(dir);

  if (level === 0) {
    findings.push({
      rule: "SLSA_LEVEL_0",
      description:
        "No build script or CI workflow found — project has no verifiable build process (SLSA Level 0)",
      severity: "info",
      recommendation:
        "Add a GitHub Actions workflow or Dockerfile to establish a reproducible build. " +
        "Aim for SLSA Level 2 by using slsa-framework/slsa-github-generator.",
    });
  } else if (level === 1) {
    findings.push({
      rule: "SLSA_NO_PROVENANCE",
      description:
        "Build workflow found but no signed provenance or attestation detected (SLSA Level 1). " +
        "Artifacts cannot be cryptographically verified.",
      severity: "low",
      recommendation:
        "Add `slsa-framework/slsa-github-generator` or `actions/attest-build-provenance` to " +
        "your release workflow to reach SLSA Level 2. Consider cosign for container signing.",
    });
  } else if (level === 2) {
    findings.push({
      rule: "SLSA_UNSIGNED_ARTIFACTS",
      description:
        "Signed provenance action detected but no hermetic build or attestation file found (SLSA Level 2). " +
        "Build inputs are not fully verified.",
      severity: "info",
      recommendation:
        "Pick the L3 path that fits your ecosystem. " +
        "For npm packages: add `--provenance` to `npm publish` and grant `id-token: write` " +
        "permission in the publish job - npm 9.5+ then produces Sigstore-signed, Rekor-logged " +
        "provenance bound to the workflow identity. " +
        "For other ecosystems: call `slsa-framework/slsa-github-generator` from a reusable " +
        "workflow (`workflow_call`) and attach the `provenance.intoto.jsonl` to each release.",
    });
  }
  // Level 3: no findings — fully compliant

  return findings;
}
