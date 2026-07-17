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
 *   3 — Hermetic build + a VALID parsed provenance statement
 *
 * Scope (v5.15.0): provenance files are now PARSED and structurally validated
 * (in-toto Statement / DSSE envelope / Sigstore bundle -> SLSA predicate type +
 * digested subjects), not merely detected by filename - a present-but-empty or
 * malformed provenance file no longer counts. This validates STRUCTURE and
 * binding fields, not the cryptographic signature / Fulcio certificate chain /
 * Rekor inclusion proof; full offline signature verification is a follow-up.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { MAX_FILE_SIZE } from "./patterns.js";

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

/**
 * Attestation STATEMENT files (an in-toto/DSSE/sigstore provenance document).
 * cosign.pub is a public key, not a statement, so it is handled separately -
 * it must never on its own be treated as "provenance is present".
 */
const ATTESTATION_STATEMENT_FILES = [
  "provenance.json",
  "attestation.json",
  "provenance.intoto.jsonl",
  ".sigstore",
];

/** Recognised in-toto Statement type URIs. */
const INTOTO_STATEMENT_TYPES = new Set([
  "https://in-toto.io/Statement/v1",
  "https://in-toto.io/Statement/v0.1",
]);

/** SLSA provenance predicate type prefixes (v0.1, v0.2, v1). */
const SLSA_PREDICATE_PREFIX = "https://slsa.dev/provenance/";

export interface AttestationResult {
  /** An attestation STATEMENT file exists (in dir / dist / .github). */
  present: boolean;
  /** The file parses as a real in-toto/DSSE/sigstore SLSA provenance statement. */
  valid: boolean;
  /**
   * What the present file is:
   *  - "slsa": a valid SLSA provenance statement (valid=true)
   *  - "non-slsa-attestation": a valid in-toto attestation with a non-SLSA
   *     predicate (e.g. an SBOM/SPDX attestation) - legitimate, NOT flagged
   *  - "malformed": present but not a usable statement (placeholder/garbage,
   *     or a SLSA statement missing digested subjects) - this is the problem case
   */
  kind?: "slsa" | "non-slsa-attestation" | "malformed";
  /** Path of the file that was inspected, if any. */
  file?: string;
  /** in-toto statement predicateType, when extractable. */
  predicateType?: string;
  /** Number of attested subjects (artifacts), when extractable. */
  subjectCount?: number;
  /** Builder identity from the SLSA predicate, when extractable. */
  builderId?: string;
  /** Why an existing file was judged not-valid-SLSA (for the finding message). */
  reason?: string;
}

/**
 * Extract and structurally validate an in-toto statement from a parsed value
 * that may be the statement itself, a DSSE envelope (base64 payload), or a
 * Sigstore bundle wrapping a DSSE envelope. Returns the statement or null.
 *
 * NOTE: this validates STRUCTURE and binding fields (statement type, SLSA
 * predicate type, subject digests), NOT the cryptographic signature / Fulcio
 * certificate chain / Rekor inclusion proof. Full signature verification is a
 * separate, heavier step (see verifySLSA doc). We never claim more than we do.
 */
function extractInTotoStatement(parsed: unknown, depth = 0): Record<string, unknown> | null {
  // Bound the unwrap chain: the input is an untrusted attestation file, and a
  // crafted bundle/DSSE that nests another envelope in its payload must not
  // recurse without limit. A real statement is at most bundle -> DSSE -> stmt.
  if (depth > 4) return null;
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;

  // Sigstore bundle -> unwrap its dsseEnvelope.
  if (typeof obj.mediaType === "string" && obj.mediaType.includes("sigstore.bundle")) {
    const env = obj.dsseEnvelope ?? (obj.content as Record<string, unknown> | undefined)?.dsseEnvelope;
    if (env) return extractInTotoStatement(env, depth + 1);
  }

  // DSSE envelope -> decode the base64 payload to the statement.
  if (typeof obj.payload === "string" && obj.payloadType !== undefined) {
    try {
      const decoded = Buffer.from(obj.payload, "base64").toString("utf-8");
      return extractInTotoStatement(JSON.parse(decoded), depth + 1);
    } catch {
      return null;
    }
  }

  // Bare in-toto statement.
  if (typeof obj._type === "string" && INTOTO_STATEMENT_TYPES.has(obj._type)) {
    return obj;
  }
  return null;
}

/**
 * Classify a well-formed in-toto statement: valid SLSA provenance, a valid but
 * non-SLSA attestation (SBOM/SPDX/other predicate), or a malformed SLSA
 * statement (SLSA predicate but no digested subject). Never throws.
 */
function classifyStatement(stmt: Record<string, unknown>): AttestationResult {
  const predicateType = typeof stmt.predicateType === "string" ? stmt.predicateType : undefined;

  // A valid in-toto statement whose predicate is NOT SLSA provenance (e.g. an
  // SBOM/SPDX attestation) is legitimate - it just is not SLSA provenance.
  if (!predicateType || !predicateType.startsWith(SLSA_PREDICATE_PREFIX)) {
    return {
      present: true,
      valid: false,
      kind: "non-slsa-attestation",
      predicateType,
      reason: `in-toto attestation with a non-SLSA predicate${predicateType ? ` (${predicateType})` : ""}`,
    };
  }

  const subject = Array.isArray(stmt.subject) ? stmt.subject : [];
  const digestedSubjects = subject.filter(
    (s) => s && typeof s === "object" && (s as { digest?: unknown }).digest &&
      typeof (s as { digest?: unknown }).digest === "object",
  );
  if (digestedSubjects.length === 0) {
    return {
      present: true,
      valid: false,
      kind: "malformed",
      predicateType,
      reason: "SLSA provenance statement has no digested subject",
    };
  }

  const predicate = (stmt.predicate ?? {}) as Record<string, unknown>;
  const builder = (predicate.builder ?? (predicate.runDetails as Record<string, unknown> | undefined)?.builder) as
    | { id?: unknown }
    | undefined;
  const builderId = builder && typeof builder.id === "string" ? builder.id : undefined;

  return {
    present: true,
    valid: true,
    kind: "slsa",
    predicateType,
    subjectCount: digestedSubjects.length,
    builderId,
  };
}

/**
 * Parse and structurally validate the project's attestation statement, if any.
 * Replaces the old "a file named provenance.json exists" heuristic: a present
 * but empty / malformed / non-provenance file is reported as NOT valid, so it
 * can no longer inflate the SLSA level or masquerade as real provenance.
 */
export function parseAttestation(dir: string): AttestationResult {
  const searchDirs = [dir, path.join(dir, "dist"), path.join(dir, ".github")];
  for (const filename of ATTESTATION_STATEMENT_FILES) {
    for (const base of searchDirs) {
      const filePath = path.join(base, filename);
      if (!fs.existsSync(filePath)) continue;

      // Bound the read like every other scanner: a real provenance file is a few
      // KB, so an oversized one is skipped rather than read into memory (a
      // committed multi-hundred-MB file must not become a memory DoS).
      let content: string;
      try {
        if (fs.statSync(filePath).size > MAX_FILE_SIZE) continue;
        content = fs.readFileSync(filePath, "utf-8");
      } catch {
        return { present: true, valid: false, kind: "malformed", file: filePath, reason: "unreadable" };
      }

      // .intoto.jsonl is one DSSE envelope per line; try each line and prefer a
      // valid SLSA line, falling back to the first classifiable statement.
      const candidates = filename.endsWith(".jsonl")
        ? content.split(/\r?\n/).filter((l) => l.trim().length > 0)
        : [content];

      let firstClassified: AttestationResult | null = null;
      for (const candidate of candidates) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(candidate);
        } catch {
          continue;
        }
        const stmt = extractInTotoStatement(parsed);
        if (!stmt) continue;
        const cls = { ...classifyStatement(stmt), file: filePath };
        if (cls.valid) return cls;
        firstClassified ??= cls;
      }
      return (
        firstClassified ?? {
          present: true,
          valid: false,
          kind: "malformed",
          file: filePath,
          reason: "not a valid in-toto/DSSE statement",
        }
      );
    }
  }
  return { present: false, valid: false };
}

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
  // A VALID parsed provenance statement, not merely a file named provenance.json
  // (an empty/garbage file no longer inflates the level - v5.15.0).
  const attestation = parseAttestation(dir).valid;

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

  // A provenance file that is present but MALFORMED (a placeholder/garbage file,
  // or a SLSA statement with no digested subject) is worse than none: it looks
  // like verifiable provenance but attests nothing. A valid non-SLSA in-toto
  // attestation (e.g. an SBOM/SPDX attestation) is legitimate and NOT flagged.
  const att = parseAttestation(dir);
  if (att.present && att.kind === "malformed") {
    findings.push({
      rule: "SLSA_PROVENANCE_INVALID",
      description:
        `A provenance file (${att.file ? path.basename(att.file) : "provenance"}) is present but is ` +
        `not usable SLSA provenance: ${att.reason ?? "unparseable"}. It does not actually attest the build.`,
      severity: "medium",
      confidence: 0.9,
      category: "supply-chain",
      recommendation:
        "Regenerate provenance with a real tool (npm publish --provenance, " +
        "actions/attest-build-provenance, or slsa-github-generator). A placeholder or malformed " +
        "provenance file gives a false sense of verifiability - verify the artifact digest in the " +
        "statement subject matches the published artifact.",
    });
  }

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
