/**
 * SLSA Provenance Verifier
 *
 * Grades a project's build-provenance posture from its build configuration,
 * its GitHub Actions workflows and any attestation statement it ships, and
 * reports WHICH checks produced that grade and which were never run.
 *
 * Levels on THIS TOOL'S scale. Read them as a posture score computed from a
 * static read of a repository, not as a certification against the SLSA v1.0
 * Build track (see NOT_ASSESSED below for why no static read can be one):
 *   0 - No build script and no CI workflow: no build process to reason about
 *   1 - A build script or a CI workflow exists
 *   2 - A signing / attestation action appears in a workflow, or a
 *       `npm publish --provenance` that is not paired with the OIDC permission
 *       it needs to actually mint provenance
 *   3 - Either the slsa-framework/slsa-github-generator reusable workflow, or a
 *       SINGLE job that both runs `npm publish --provenance` and holds
 *       `id-token: write`
 *
 * (unreleased, issues 188/189/190) - three ways this module used to report more than
 * it had done, and what replaced each:
 *
 *   - The DSSE `signatures` member was never read, so an envelope with
 *     `signatures: []`, one with no `signatures` key, and one carrying
 *     attacker-supplied bytes were all reported exactly like a signed one.
 *     An envelope with no usable signature is now `kind: "malformed"`, and
 *     `signatureStatus` states which of the three cases a caller is looking at.
 *   - A subject whose digest set was `{}` or `[]` passed a bare
 *     `typeof digest === "object"` test and was graded as a usable subject.
 *     `isUsableDigestSet` now requires a non-empty algorithm-to-value map of
 *     non-empty strings.
 *   - Levels 2 and 3 came from regexes over the RAW concatenated text of every
 *     workflow file, so a commented-out `# TODO: npm publish --provenance`
 *     produced a 3, and the `--provenance` step and the `id-token: write`
 *     permission never had to belong to the same job (or even the same file).
 *     Text matching now runs over comment-stripped content, and the npm-native
 *     Level 3 path resolves both signals inside one parsed job.
 *
 * WHAT THIS MODULE NEVER DOES - on every path, at every level. `SLSA_NOT_ASSESSED`
 * below is carried in `SLSAAssessment.notAssessed` into the report so the number
 * is never published without it:
 *   - it verifies no cryptographic signature. No key material, no Fulcio
 *     certificate chain, no Rekor inclusion proof is fetched or checked.
 *   - it binds no attested subject digest to any artefact, published or in the
 *     scanned tree.
 *   - it establishes none of the build-platform properties SLSA v1.0 Build L3
 *     actually defines (build isolation, provenance the build cannot forge).
 *     Those are properties of a build service; nothing read from a checkout can
 *     establish them.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { MAX_FILE_SIZE } from "./patterns.js";
import { parseWorkflow, stripYamlComments, type WfJob, type WorkflowAst } from "./workflow-ast.js";

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

/**
 * References to the slsa-github-generator reusable workflow, which IS a SLSA
 * L3 builder: it runs on a GitHub-hosted runner the calling repository cannot
 * influence and emits provenance the caller cannot forge.
 *
 * Matched as text rather than through the AST on purpose: the reference is
 * valid at `jobs.<id>.uses`, at `steps[].uses` and in a reusable-workflow call,
 * and one regex over comment-stripped content covers all three. The input is
 * comment-stripped (unreleased), so a reference that only exists in a comment no
 * longer counts.
 */
const SLSA_GENERATOR_PATTERNS = [
  /slsa-framework\/slsa-github-generator.*@[0-9a-f]{40}/i,
  /uses:\s+slsa-framework\/slsa-github-generator/i,
];

/**
 * Modern canonical SLSA Level 3 path for npm packages.
 *
 * `npm publish --provenance` (npm >= 9.5, mandatory under npm Trusted Publishing
 * since 11.5) generates a Sigstore-signed provenance statement using the GitHub
 * Actions OIDC identity, publishes it to the npm registry, and records it in
 * the public Rekor transparency log.
 *
 * (unreleased, issue 190): both signals must now resolve to the SAME JOB. The pair
 * used to be tested against the concatenated text of every workflow file, so an
 * `id-token: write` in an unrelated CodeQL job satisfied the permission half for
 * a publish step that could never use it - and a `--provenance` inside a `#`
 * comment satisfied the other half. Neither configuration can mint provenance,
 * and both were graded 3.
 */
const NPM_PROVENANCE_PATTERN = /npm\s+publish[^\n]*--provenance/i;

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

/**
 * Checks this module never performs, in plain words, for the report (unreleased).
 *
 * This list is the reason a level is publishable at all. A number with no way
 * to express what it did not look at is the defect issues 188/189/190 all
 * describe; carrying this next to the number is what makes "not assessed" a
 * state distinct from "checked and passed".
 */
export const SLSA_NOT_ASSESSED: readonly string[] = [
  "cryptographic signature verification: no key material, Fulcio certificate chain or Rekor inclusion proof is checked, so a structurally correct signature is indistinguishable here from a trusted one",
  "digest binding: no attested subject digest is compared against any artefact, published or in the scanned tree",
  "build-platform properties: SLSA v1.0 Build L3 defines build isolation and unforgeable provenance, which are properties of the build service and cannot be established by reading a repository",
];

/**
 * Signature state of the envelope an attestation statement arrived in (unreleased).
 *
 *  - "not-applicable": the file is a bare in-toto statement with no envelope,
 *    so there is no `signatures` member to read. Note this is NOT reassurance:
 *    such a file carries no signer at all.
 *  - "absent": a DSSE / Sigstore envelope IS present and carries no usable
 *    signature (`signatures` missing, `[]`, or entries with no `sig` string).
 *    Structurally detectable, and reported.
 *  - "present-unverified": at least one signature is present and was NOT
 *    verified. This tool cannot tell a valid signature from a forged one.
 */
export type SignatureStatus = "not-applicable" | "absent" | "present-unverified";

export interface AttestationResult {
  /** An attestation STATEMENT file exists (in dir / dist / .github). */
  present: boolean;
  /**
   * @deprecated Reads as a verification verdict and is not one. Identical to
   * `structurallyValid`, kept so existing consumers keep compiling. Use
   * `structurallyValid` together with `signatureStatus`: this boolean is true
   * for a statement whose SIGNATURE WAS NEVER CHECKED.
   */
  valid: boolean;
  /**
   * The file parses as an in-toto/DSSE/sigstore SLSA provenance statement with
   * a usable digested subject. Says nothing about any signature.
   */
  structurallyValid: boolean;
  /** What was found in the envelope's `signatures` member. */
  signatureStatus?: SignatureStatus;
  /** How many usable signature entries the envelope carried (0 unless present-unverified). */
  signatureCount?: number;
  /** Checks not performed on this statement. Populated whenever `present` is true. */
  checksNotPerformed?: readonly string[];
  /**
   * What the present file is:
   *  - "slsa": a structurally valid SLSA provenance statement
   *  - "non-slsa-attestation": a valid in-toto attestation with a non-SLSA
   *     predicate (e.g. an SBOM/SPDX attestation) - legitimate, NOT flagged
   *  - "malformed": present but not a usable statement (placeholder/garbage, a
   *     SLSA statement with no usably digested subject, or an envelope with no
   *     usable signature) - this is the problem case
   */
  kind?: "slsa" | "non-slsa-attestation" | "malformed";
  /** Path of the file that was inspected, if any. */
  file?: string;
  /** in-toto statement predicateType, when extractable. */
  predicateType?: string;
  /** Number of attested subjects carrying a usable digest set, when extractable. */
  subjectCount?: number;
  /** Builder identity from the SLSA predicate, when extractable. UNVERIFIED: self-declared by the file. */
  builderId?: string;
  /** Why an existing file was judged not-valid-SLSA (for the finding message). */
  reason?: string;
}

/** What a SLSA level was computed from, and what it left unexamined (unreleased). */
export interface SLSAAssessment {
  /** Numeric level 0-3 on this tool's scale (see the module header). */
  level: number;
  /** Signals that were found and that produced the level, in the order applied. */
  basis: string[];
  /** Checks that were never run. Never empty - see SLSA_NOT_ASSESSED. */
  notAssessed: readonly string[];
  /** The attestation verdict this level was computed against. */
  attestation: AttestationResult;
}

interface Unwrapped {
  statement: Record<string, unknown> | null;
  signatureStatus: SignatureStatus;
  signatureCount: number;
}

/**
 * Read a DSSE envelope's `signatures` member (unreleased, issue 188).
 *
 * The DSSE specification makes `signatures` REQUIRED and a signed envelope
 * carries at least one entry with a `sig` value. An entry with no `sig` string
 * signs nothing, so an array of such entries is the same as an empty one.
 *
 * This establishes only that SOMETHING is there to be verified. It performs no
 * verification: see SLSA_NOT_ASSESSED.
 */
function readSignatures(obj: Record<string, unknown>): { status: SignatureStatus; count: number } {
  const signatures = obj.signatures;
  if (!Array.isArray(signatures)) return { status: "absent", count: 0 };
  const usable = signatures.filter(
    (entry) =>
      entry !== null &&
      typeof entry === "object" &&
      typeof (entry as { sig?: unknown }).sig === "string" &&
      (entry as { sig: string }).sig.trim() !== "",
  );
  return usable.length === 0
    ? { status: "absent", count: 0 }
    : { status: "present-unverified", count: usable.length };
}

/**
 * Extract an in-toto statement from a parsed value that may be the statement
 * itself, a DSSE envelope (base64 payload), or a Sigstore bundle wrapping a
 * DSSE envelope, and report the envelope's signature state alongside it.
 *
 * NOTE: this validates STRUCTURE and binding fields (statement type, SLSA
 * predicate type, subject digests) and reads the PRESENCE of signatures. It
 * verifies no signature. We never claim more than we do.
 */
function extractInTotoStatement(parsed: unknown, depth = 0): Unwrapped {
  const none: Unwrapped = { statement: null, signatureStatus: "not-applicable", signatureCount: 0 };
  // Bound the unwrap chain: the input is an untrusted attestation file, and a
  // crafted bundle/DSSE that nests another envelope in its payload must not
  // recurse without limit. A real statement is at most bundle -> DSSE -> stmt.
  if (depth > 4) return none;
  if (!parsed || typeof parsed !== "object") return none;
  const obj = parsed as Record<string, unknown>;

  // Sigstore bundle -> unwrap its dsseEnvelope.
  if (typeof obj.mediaType === "string" && obj.mediaType.includes("sigstore.bundle")) {
    const env = obj.dsseEnvelope ?? (obj.content as Record<string, unknown> | undefined)?.dsseEnvelope;
    if (env) return extractInTotoStatement(env, depth + 1);
  }

  // DSSE envelope -> decode the base64 payload to the statement. The envelope's
  // signature state belongs to the statement it carries and overrides whatever
  // an inner layer reported.
  if (typeof obj.payload === "string" && obj.payloadType !== undefined) {
    const sig = readSignatures(obj);
    let inner: Unwrapped;
    try {
      const decoded = Buffer.from(obj.payload, "base64").toString("utf-8");
      inner = extractInTotoStatement(JSON.parse(decoded), depth + 1);
    } catch {
      inner = none;
    }
    return { statement: inner.statement, signatureStatus: sig.status, signatureCount: sig.count };
  }

  // Bare in-toto statement: no envelope exists, so there is no signature member
  // to read - which is not the same as an envelope that carries none.
  if (typeof obj._type === "string" && INTOTO_STATEMENT_TYPES.has(obj._type)) {
    return { statement: obj, signatureStatus: "not-applicable", signatureCount: 0 };
  }
  return none;
}

/**
 * A usable in-toto DigestSet (unreleased, issue 189): a plain object, never an
 * array, with at least one entry, every entry mapping a non-empty algorithm
 * name to a non-empty string value.
 *
 * The previous test was `digest && typeof digest === "object"`, which in
 * JavaScript is also satisfied by `{}` and by `[]`. A digest set with no
 * entries identifies no artefact, so a statement carrying one binds to nothing
 * - exactly the condition the caller exists to catch. `{ sha256: 12345 }` is
 * rejected for the same reason: a non-string value is not a digest.
 */
function isUsableDigestSet(digest: unknown): boolean {
  if (!digest || typeof digest !== "object" || Array.isArray(digest)) return false;
  const entries = Object.entries(digest as Record<string, unknown>);
  if (entries.length === 0) return false;
  return entries.every(
    ([algorithm, value]) =>
      algorithm.trim() !== "" && typeof value === "string" && value.trim() !== "",
  );
}

/**
 * Classify a well-formed in-toto statement: structurally valid SLSA provenance,
 * a valid but non-SLSA attestation (SBOM/SPDX/other predicate), or a malformed
 * SLSA statement (no usable signature, or no usably digested subject).
 * Never throws.
 */
function classifyStatement(stmt: Record<string, unknown>, unwrapped: Unwrapped): AttestationResult {
  const predicateType = typeof stmt.predicateType === "string" ? stmt.predicateType : undefined;
  const envelope = {
    signatureStatus: unwrapped.signatureStatus,
    signatureCount: unwrapped.signatureCount,
    checksNotPerformed: SLSA_NOT_ASSESSED,
  };

  // A valid in-toto statement whose predicate is NOT SLSA provenance (e.g. an
  // SBOM/SPDX attestation) is legitimate - it just is not SLSA provenance.
  if (!predicateType || !predicateType.startsWith(SLSA_PREDICATE_PREFIX)) {
    return {
      present: true,
      valid: false,
      structurallyValid: false,
      ...envelope,
      kind: "non-slsa-attestation",
      predicateType,
      reason: `in-toto attestation with a non-SLSA predicate${predicateType ? ` (${predicateType})` : ""}`,
    };
  }

  // An envelope that carries no usable signature attests nothing: anyone who
  // can write the file can author it. Checked before the subject, so an
  // unsigned envelope reports the reason a reader can act on (issue 188).
  if (unwrapped.signatureStatus === "absent") {
    return {
      present: true,
      valid: false,
      structurallyValid: false,
      ...envelope,
      kind: "malformed",
      predicateType,
      reason:
        "the DSSE envelope carries no usable signature, so nothing binds this statement to a signer",
    };
  }

  const subject = Array.isArray(stmt.subject) ? stmt.subject : [];
  const digestedSubjects = subject.filter(
    (s) => s && typeof s === "object" && isUsableDigestSet((s as { digest?: unknown }).digest),
  );
  if (digestedSubjects.length === 0) {
    return {
      present: true,
      valid: false,
      structurallyValid: false,
      ...envelope,
      kind: "malformed",
      predicateType,
      reason: "SLSA provenance statement has no subject carrying a usable digest set",
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
    structurallyValid: true,
    ...envelope,
    kind: "slsa",
    predicateType,
    subjectCount: digestedSubjects.length,
    builderId,
  };
}

/**
 * Parse and structurally validate the project's attestation statement, if any.
 *
 * `valid` / `structurallyValid` mean the file PARSES as SLSA provenance with a
 * usable digested subject and arrived in an envelope that carries something to
 * verify. They do not mean the signature was checked - read `signatureStatus`
 * and `checksNotPerformed` for that.
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
        return {
          present: true,
          valid: false,
          structurallyValid: false,
          checksNotPerformed: SLSA_NOT_ASSESSED,
          kind: "malformed",
          file: filePath,
          reason: "unreadable",
        };
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
        const unwrapped = extractInTotoStatement(parsed);
        if (!unwrapped.statement) continue;
        const cls = { ...classifyStatement(unwrapped.statement, unwrapped), file: filePath };
        if (cls.structurallyValid) return cls;
        firstClassified ??= cls;
      }
      return (
        firstClassified ?? {
          present: true,
          valid: false,
          structurallyValid: false,
          checksNotPerformed: SLSA_NOT_ASSESSED,
          kind: "malformed",
          file: filePath,
          reason: "not a valid in-toto/DSSE statement",
        }
      );
    }
  }
  return { present: false, valid: false, structurallyValid: false };
}

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

interface ParsedWorkflow {
  /** Basename only: a scan target can be an absolute runner path, which must not reach a report. */
  name: string;
  /** Comment-stripped file content, for the text matchers. */
  text: string;
  ast: WorkflowAst;
}

/**
 * Read every workflow file once: comment-stripped text for the reference
 * matchers, and a parsed AST for anything that has to know WHICH JOB a signal
 * belongs to.
 */
function readWorkflows(workflowFiles: string[]): ParsedWorkflow[] {
  const parsed: ParsedWorkflow[] = [];
  for (const file of workflowFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    parsed.push({
      name: path.basename(file),
      text: stripYamlComments(content),
      ast: parseWorkflow(content),
    });
  }
  return parsed;
}

/**
 * Whether `id-token: write` is in effect for this job.
 *
 * GitHub semantics, and the reason this is not a substring search: a job-level
 * `permissions:` block REPLACES the workflow-level one outright. A job that
 * declares `permissions: {contents: read}` does NOT inherit a workflow-level
 * `id-token: write`, and a publish step in it cannot mint provenance.
 */
function jobHasOidcWrite(ast: WorkflowAst, job: WfJob): boolean {
  const effective = job.permissions.declared ? job.permissions : ast.permissions;
  if (!effective.declared) return false;
  if (effective.writeAll) return true;
  return effective.scopes["id-token"] === "write";
}

/**
 * The job that could actually mint npm provenance: one job whose own steps run
 * `npm publish --provenance` and which holds `id-token: write` (issue 190).
 */
function findNpmProvenanceJob(
  workflows: ParsedWorkflow[],
): { file: string; jobId: string } | undefined {
  for (const workflow of workflows) {
    for (const job of workflow.ast.jobs) {
      const publishes = job.steps.some(
        (step) => step.run !== undefined && NPM_PROVENANCE_PATTERN.test(step.run),
      );
      if (publishes && jobHasOidcWrite(workflow.ast, job)) {
        return { file: workflow.name, jobId: job.id };
      }
    }
  }
  return undefined;
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
 * Grade a project directory AND report what the grade was computed from.
 *
 * Prefer this over getSLSALevel() anywhere the result is rendered: the number
 * alone cannot express "not assessed", which is the whole of issues 188/189/190.
 */
export function assessSLSA(dir: string): SLSAAssessment {
  const attestation = parseAttestation(dir);
  const basis: string[] = [];
  const done = (level: number): SLSAAssessment => ({
    level,
    basis,
    notAssessed: SLSA_NOT_ASSESSED,
    attestation,
  });

  const workflowFiles = hasWorkflowFiles(dir);
  const buildScript = hasBuildScript(dir);
  if (buildScript) basis.push("a build script (Dockerfile/Makefile/build.sh/...) is present");
  if (workflowFiles.length > 0) {
    basis.push(`${workflowFiles.length} GitHub Actions workflow file(s) under .github/workflows`);
  }

  // Level 0: no build evidence at all
  if (workflowFiles.length === 0 && !buildScript) return done(0);
  // Level 1: build script only, nothing to read for a higher signal
  if (workflowFiles.length === 0) return done(1);

  const workflows = readWorkflows(workflowFiles);
  // Comment-stripped, so a reference that only exists in a `#` comment cannot
  // contribute to any level (issue 190).
  const corpus = workflows.map((workflow) => workflow.text).join("\n");

  let level = 1;

  const generatorRef = SLSA_GENERATOR_PATTERNS.some((p) => p.test(corpus));
  // `workflow_call` is the TRIGGER that makes a workflow callable by another
  // workflow. It is NOT an isolation or hermeticity property, and hermeticity
  // is not a SLSA v1.0 Build L3 requirement (it was dropped from the Build
  // track). It is named here for what it is: the caller/callee split the
  // slsa-github-generator builder is invoked through. This release renamed this from
  // HERMETIC_BUILD_PATTERNS, which also matched a bare `reusable_workflow`
  // string that is not a workflow key at all.
  const calledAsReusableWorkflow = workflows.some((workflow) =>
    workflow.ast.triggers.includes("workflow_call"),
  );

  if (generatorRef && (calledAsReusableWorkflow || attestation.structurallyValid)) {
    level = 3;
    basis.push("a workflow references the slsa-framework/slsa-github-generator builder");
    basis.push(
      calledAsReusableWorkflow
        ? "a workflow declares the workflow_call trigger, so the builder is invoked as a reusable workflow"
        : "a structurally valid SLSA provenance statement is present in the tree",
    );
  } else {
    const npmJob = findNpmProvenanceJob(workflows);
    if (npmJob) {
      level = 3;
      basis.push(
        `job "${npmJob.jobId}" in ${npmJob.file} runs \`npm publish --provenance\` and has \`id-token: write\` in effect`,
      );
    } else if (SLSA_LEVEL2_PATTERNS.some((p) => p.test(corpus))) {
      level = 2;
      basis.push("a signing or attestation action is referenced by a workflow");
    }
  }

  // A provenance file that is present but does not parse as a usable statement
  // used to coexist with a 3/3 headline in the same report, which said two
  // contradictory things at once (issue 190). The attestation verdict now feeds
  // back into the level instead of sitting beside it.
  if (attestation.present && attestation.kind === "malformed" && level > 2) {
    level = 2;
    basis.push(
      `capped at 2: ${attestation.file ? path.basename(attestation.file) : "a provenance file"} is present but is not a usable SLSA statement (${attestation.reason ?? "unparseable"})`,
    );
  }

  return done(level);
}

/**
 * Determine SLSA level (0-3) for a project directory.
 *
 * Kept for API compatibility. A bare number cannot say what it did not check,
 * so anything that RENDERS the level should call assessSLSA() instead and show
 * `basis` and `notAssessed` next to it.
 *
 * @returns Numeric level 0-3
 */
export function getSLSALevel(dir: string): number {
  return assessSLSA(dir).level;
}

/**
 * Verify SLSA posture of a project directory and return findings for gaps.
 */
export function verifySLSA(dir: string): Finding[] {
  const findings: Finding[] = [];
  const assessment = assessSLSA(dir);
  const level = assessment.level;
  const att = assessment.attestation;
  const attName = att.file ? path.basename(att.file) : "provenance";

  // An envelope with no usable signature is reported under its own rule, not
  // folded into SLSA_PROVENANCE_INVALID: the remediation is different (sign it,
  // rather than regenerate it) and a SARIF consumer should be able to select
  // for it (unreleased, issue 188).
  if (att.present && att.kind === "malformed" && att.signatureStatus === "absent") {
    findings.push({
      rule: "SLSA_ATTESTATION_UNSIGNED",
      description:
        `The attestation envelope in ${attName} carries no usable signature ` +
        `(its DSSE 'signatures' member is missing, empty, or has no 'sig' value). ` +
        `Nothing binds the statement - including its self-declared builder identity - to any signer, ` +
        `so anyone able to write this file can author it.`,
      severity: "medium",
      confidence: 0.9,
      category: "supply-chain",
      recommendation:
        "Regenerate the attestation with a tool that signs it (npm publish --provenance, " +
        "actions/attest-build-provenance, or slsa-github-generator), and keep the signature in the " +
        "envelope. Note that this scanner checks only that a signature is PRESENT: it verifies no " +
        "signature, certificate chain or transparency-log inclusion proof.",
    });
  } else if (att.present && att.kind === "malformed") {
    // A provenance file that is present but MALFORMED (a placeholder/garbage file,
    // or a SLSA statement with no usably digested subject) is worse than none: it
    // looks like verifiable provenance but attests nothing. A valid non-SLSA
    // in-toto attestation (e.g. an SBOM attestation) is legitimate and NOT flagged.
    findings.push({
      rule: "SLSA_PROVENANCE_INVALID",
      description:
        `A provenance file (${attName}) is present but is ` +
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

  // A structurally valid statement is the case where a reader is most likely to
  // over-read the result, so the limit travels with it into every format that
  // renders findings - which is the only place the caveat reaches SARIF, GitLab
  // and JUnit at all (unreleased, issue 188).
  if (att.present && att.structurallyValid) {
    const signatureNote =
      att.signatureStatus === "present-unverified"
        ? `${att.signatureCount ?? 0} signature(s) are present and were NOT verified`
        : "the statement is bare in-toto with no envelope, so it carries no signature at all";
    findings.push({
      rule: "SLSA_SIGNATURE_NOT_VERIFIED",
      description:
        `${attName} was checked for STRUCTURE only: ${signatureNote}. ` +
        `Not assessed: ${SLSA_NOT_ASSESSED.join("; ")}.`,
      severity: "info",
      confidence: 1,
      category: "supply-chain",
      recommendation:
        "Treat this attestation as unverified evidence. To verify it, use a verifier that checks " +
        "the signature against a trust root and the transparency log (for example `slsa-verifier` " +
        "or `gh attestation verify`), and compare the subject digest against the artifact you " +
        "actually consume.",
    });
  }

  if (level === 0) {
    findings.push({
      rule: "SLSA_LEVEL_0",
      description:
        "No build script or CI workflow found - project has no verifiable build process (SLSA Level 0)",
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
        "Signed provenance action detected but no reusable-workflow builder or valid attestation file found (SLSA Level 2). " +
        "Build inputs are not fully verified.",
      severity: "info",
      recommendation:
        "Pick the L3 path that fits your ecosystem. " +
        "For npm packages: add `--provenance` to `npm publish` and grant `id-token: write` " +
        "permission in THE SAME JOB - npm 9.5+ then produces Sigstore-signed, Rekor-logged " +
        "provenance bound to the workflow identity. " +
        "For other ecosystems: call `slsa-framework/slsa-github-generator` from a reusable " +
        "workflow (`workflow_call`) and attach the `provenance.intoto.jsonl` to each release.",
    });
  }
  // Level 3: no gap finding. The limits of the grade are carried by
  // SLSAAssessment.notAssessed, and by SLSA_SIGNATURE_NOT_VERIFIED when a
  // statement is present.

  return findings;
}
