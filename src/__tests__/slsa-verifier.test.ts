import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { getSLSALevel, verifySLSA, parseAttestation, assessSLSA } from "../slsa-verifier.js";

let tmpDir: string;

function mkWorkflow(dir: string, filename: string, content: string) {
  const workflowDir = path.join(dir, ".github", "workflows");
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(path.join(workflowDir, filename), content);
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-slsa-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("getSLSALevel", () => {
  it("should return 0 for empty directory (no build evidence)", () => {
    expect(getSLSALevel(tmpDir)).toBe(0);
  });

  it("should return 1 when only a Dockerfile is present", () => {
    fs.writeFileSync(path.join(tmpDir, "Dockerfile"), "FROM node:20\n");
    expect(getSLSALevel(tmpDir)).toBe(1);
  });

  it("should return 1 when a workflow exists but no signing", () => {
    mkWorkflow(tmpDir, "ci.yml", `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
`);
    expect(getSLSALevel(tmpDir)).toBe(1);
  });

  it("should return 2 when cosign signing action is used", () => {
    mkWorkflow(tmpDir, "release.yml", `
on: release
jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-action@v3
`);
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  it("should return 2 when actions/attest-build-provenance is used", () => {
    mkWorkflow(tmpDir, "release.yml", `
on: release
jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/attest-build-provenance@v1
`);
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  it("should return 2 when slsa-github-generator is used (without hermetic build)", () => {
    mkWorkflow(tmpDir, "release.yml", `
uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1
`);
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  it("should return 3 when slsa-github-generator with SHA pin and workflow_call", () => {
    mkWorkflow(tmpDir, "release.yml", `
on:
  workflow_call:
    inputs:
      artifact:
        type: string
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator@abc1234567890abcdef1234567890abcdef123456
`);
    expect(getSLSALevel(tmpDir)).toBe(3);
  });

  it("does not grant Level 3 when the generator and workflow_call live in different files", () => {
    // Same pair of signals as the test above, split across two workflows.
    // Combining them over the concatenated corpus is the same defect issue 190
    // reported for the npm-native path: a callable CodeQL workflow plus a
    // generator mention in an unrelated release file is not a builder invocation.
    mkWorkflow(tmpDir, "callable.yml", `
on:
  workflow_call:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`);
    mkWorkflow(tmpDir, "release.yml", `
on: push
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator@abc1234567890abcdef1234567890abcdef123456
`);
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  it("should return 3 when slsa-github-generator SHA + a VALID provenance statement", () => {
    mkWorkflow(tmpDir, "release.yml", `
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator@abc1234567890abcdef1234567890abcdef123456
`);
    fs.writeFileSync(
      path.join(tmpDir, "provenance.json"),
      JSON.stringify({
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: "pkg-1.0.0.tgz", digest: { sha256: "a".repeat(64) } }],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: { buildDefinition: {}, runDetails: { builder: { id: "https://github.com/actions/runner" } } },
      }),
    );
    expect(getSLSALevel(tmpDir)).toBe(3);
  });

  it("should NOT return 3 for an empty/placeholder provenance.json (v5.15.0 honesty fix)", () => {
    mkWorkflow(tmpDir, "release.yml", `
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator@abc1234567890abcdef1234567890abcdef123456
`);
    fs.writeFileSync(path.join(tmpDir, "provenance.json"), "{}");
    // hermetic pattern present but no valid attestation and no workflow_call
    // reusable-workflow signal -> drops to Level 2, not a false Level 3.
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  it("should return 1 for Makefile without workflow", () => {
    fs.writeFileSync(path.join(tmpDir, "Makefile"), "build:\n\tnpm run build\n");
    expect(getSLSALevel(tmpDir)).toBe(1);
  });

  // -------------------------------------------------------------------------
  // npm-native L3 path: `npm publish --provenance` + OIDC `id-token: write`
  // Added v5.2.26. Mirrors the slsa-github-generator path for the npm ecosystem.
  // -------------------------------------------------------------------------

  it("should return 3 when npm publish --provenance is combined with id-token: write", () => {
    mkWorkflow(tmpDir, "ci.yml", `
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
      - run: npm publish --access public --provenance
`);
    expect(getSLSALevel(tmpDir)).toBe(3);
  });

  it("should return 2 when --provenance is present but id-token: write is missing", () => {
    // Without id-token: write the publish would fail at runtime; we refuse
    // to credit L3 for a non-functional configuration.
    mkWorkflow(tmpDir, "ci.yml", `
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance
`);
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  it("should return 1 when id-token: write is present without --provenance", () => {
    // OIDC permission alone (e.g. for AWS auth) doesn't establish provenance.
    mkWorkflow(tmpDir, "ci.yml", `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: echo "deploy"
`);
    expect(getSLSALevel(tmpDir)).toBe(1);
  });

  // CHANGED ASSERTION (unreleased, issue 190). This test previously asserted 3 for
  // exactly this fixture, with the rationale that detection "scans the
  // concatenated content of all workflows, mirroring how reviewers read a
  // repo's CI surface". That locked in the defect: an `id-token: write` in a
  // job that never publishes cannot let a publish step in a DIFFERENT job mint
  // provenance, so the configuration below produces no provenance at runtime
  // and must not be graded as though it did. The signals must resolve to one
  // job; the L2 grade is what the `--provenance` flag alone earns.
  it("does NOT grant L3 when --provenance and id-token:write are in different workflows", () => {
    mkWorkflow(tmpDir, "perms.yml", `
on: workflow_call
jobs:
  setup:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: echo perms
`);
    mkWorkflow(tmpDir, "publish.yml", `
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance --access public
`);
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  // ── unreleased, issue 190: text in a comment is not a build step ───────────────

  it("does NOT grant L2 when the only signing action reference is a comment", () => {
    mkWorkflow(tmpDir, "ci.yml", `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # - uses: sigstore/cosign-action@v3
      - run: echo not-implemented
`);
    expect(getSLSALevel(tmpDir)).toBe(1);
  });

  it("does NOT grant L3 for a commented-out publish step in the SAME job as id-token: write", () => {
    // The fixture from issue 190, tightened: both signals are in one job, so
    // job scoping alone cannot save this. Only refusing to match commented text
    // keeps it below 3.
    mkWorkflow(tmpDir, "release.yml", `
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      # TODO: we should eventually run npm publish --provenance here
      - run: echo not-implemented
`);
    expect(getSLSALevel(tmpDir)).toBe(1);
  });

  it("does NOT grant L3 when the publish job's own permissions omit id-token", () => {
    // GitHub replaces workflow-level permissions with the job-level block, so
    // this publish job does NOT hold id-token: write and cannot sign.
    mkWorkflow(tmpDir, "release.yml", `
on: push
permissions:
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: npm publish --provenance
`);
    expect(getSLSALevel(tmpDir)).toBe(2);
  });

  it("grants L3 when the publish job inherits workflow-level id-token: write", () => {
    // Positive control for the check above: with no job-level permissions block
    // the workflow-level grant DOES apply, so this is a real npm-native L3.
    mkWorkflow(tmpDir, "release.yml", `
on: push
permissions:
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance
`);
    expect(getSLSALevel(tmpDir)).toBe(3);
  });

  it("caps the level at 2 when a present attestation does not parse as a usable statement", () => {
    // Issue 190: a 3/3 headline used to coexist with SLSA_PROVENANCE_INVALID in
    // the same report, which said two contradictory things at once.
    mkWorkflow(tmpDir, "release.yml", `
on: push
permissions:
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance
`);
    fs.writeFileSync(
      path.join(tmpDir, "provenance.json"),
      JSON.stringify({
        _type: "https://in-toto.io/Statement/v1",
        subject: [],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: {},
      }),
    );
    expect(getSLSALevel(tmpDir)).toBe(2);
    expect(verifySLSA(tmpDir).some((f) => f.rule === "SLSA_PROVENANCE_INVALID")).toBe(true);
  });
});

// ─── unreleased, issue 188: the DSSE signatures member ────────────────────────────

describe("parseAttestation - signature state", () => {
  const stmt = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "pkg-1.0.0.tgz", digest: { sha256: "ab".repeat(32) } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: { runDetails: { builder: { id: "https://evil.example.com/not-a-builder" } } },
  };

  function writeEnvelope(signatures: unknown) {
    const envelope: Record<string, unknown> = {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(stmt)).toString("base64"),
    };
    if (signatures !== undefined) envelope.signatures = signatures;
    fs.writeFileSync(path.join(tmpDir, "provenance.json"), JSON.stringify(envelope));
  }

  it("rejects a DSSE envelope whose signatures array is empty", () => {
    writeEnvelope([]);
    const res = parseAttestation(tmpDir);
    expect(res.structurallyValid).toBe(false);
    expect(res.kind).toBe("malformed");
    expect(res.signatureStatus).toBe("absent");
    expect(verifySLSA(tmpDir).some((f) => f.rule === "SLSA_ATTESTATION_UNSIGNED")).toBe(true);
  });

  it("rejects a DSSE envelope with no signatures key at all", () => {
    writeEnvelope(undefined);
    const res = parseAttestation(tmpDir);
    expect(res.structurallyValid).toBe(false);
    expect(res.signatureStatus).toBe("absent");
  });

  it("rejects signature entries that carry no sig value", () => {
    writeEnvelope([{ keyid: "k" }]);
    const res = parseAttestation(tmpDir);
    expect(res.structurallyValid).toBe(false);
    expect(res.signatureStatus).toBe("absent");
  });

  it("an unsigned envelope is distinguishable from a signed one", () => {
    writeEnvelope([]);
    const unsigned = parseAttestation(tmpDir);
    writeEnvelope([{ sig: "MEUCIQ" }]);
    const signed = parseAttestation(tmpDir);
    expect(unsigned.signatureStatus).not.toBe(signed.signatureStatus);
    expect(unsigned.structurallyValid).not.toBe(signed.structurallyValid);
  });

  it("reports a present signature as unverified, never as verified", () => {
    writeEnvelope([{ sig: "MEUCIQ" }]);
    const res = parseAttestation(tmpDir);
    expect(res.structurallyValid).toBe(true);
    expect(res.signatureStatus).toBe("present-unverified");
    expect(res.signatureCount).toBe(1);
    expect(res.checksNotPerformed?.length).toBeGreaterThan(0);
    // The caveat reaches every format that renders findings, which is the only
    // route it has into SARIF, GitLab and JUnit.
    const finding = verifySLSA(tmpDir).find((f) => f.rule === "SLSA_SIGNATURE_NOT_VERIFIED");
    expect(finding).toBeDefined();
    expect(finding?.description).toContain("NOT verified");
  });

  it("marks a bare in-toto statement as having no envelope to sign", () => {
    fs.writeFileSync(path.join(tmpDir, "provenance.json"), JSON.stringify(stmt));
    const res = parseAttestation(tmpDir);
    expect(res.signatureStatus).toBe("not-applicable");
    expect(res.structurallyValid).toBe(true);
  });
});

// ─── unreleased, issue 189: the digest set ────────────────────────────────────────

describe("parseAttestation - subject digest set", () => {
  function writeSubjectDigest(digest: unknown) {
    const stmt = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "pkg-1.0.0.tgz", digest }],
      predicateType: "https://slsa.dev/provenance/v1",
      predicate: {},
    };
    fs.writeFileSync(
      path.join(tmpDir, "provenance.json"),
      JSON.stringify({
        payloadType: "application/vnd.in-toto+json",
        payload: Buffer.from(JSON.stringify(stmt)).toString("base64"),
        signatures: [{ sig: "MEUCIQ" }],
      }),
    );
  }

  it("rejects an empty digest set", () => {
    writeSubjectDigest({});
    const res = parseAttestation(tmpDir);
    expect(res.kind).toBe("malformed");
    expect(res.structurallyValid).toBe(false);
    expect(verifySLSA(tmpDir).some((f) => f.rule === "SLSA_PROVENANCE_INVALID")).toBe(true);
  });

  it("rejects an array digest rather than an algorithm-to-value map", () => {
    // A NON-empty array: Object.entries(["deadbeef"]) is [["0","deadbeef"]],
    // which would pass the length and string-value checks. The Array.isArray
    // guard is the only thing that rejects this shape. An empty array is
    // already rejected by the length check that the empty-object test pins,
    // so writeSubjectDigest([]) would stay green if Array.isArray were deleted.
    writeSubjectDigest(["deadbeef"]);
    expect(parseAttestation(tmpDir).kind).toBe("malformed");
  });

  it("rejects a digest whose values are not strings", () => {
    writeSubjectDigest({ sha256: 12345 });
    expect(parseAttestation(tmpDir).kind).toBe("malformed");
  });

  it("rejects a digest whose value is an empty string", () => {
    writeSubjectDigest({ sha256: "" });
    expect(parseAttestation(tmpDir).kind).toBe("malformed");
  });

  it("accepts a real digest set and counts only usable subjects", () => {
    const stmt = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [
        { name: "empty", digest: {} },
        { name: "real", digest: { sha256: "ab".repeat(32) } },
      ],
      predicateType: "https://slsa.dev/provenance/v1",
      predicate: {},
    };
    fs.writeFileSync(
      path.join(tmpDir, "provenance.json"),
      JSON.stringify({
        payloadType: "application/vnd.in-toto+json",
        payload: Buffer.from(JSON.stringify(stmt)).toString("base64"),
        signatures: [{ sig: "MEUCIQ" }],
      }),
    );
    const res = parseAttestation(tmpDir);
    expect(res.structurallyValid).toBe(true);
    expect(res.subjectCount).toBe(1);
  });
});

// ─── Unreleased: the grade carries what it was computed from ─────────────────────

describe("assessSLSA", () => {
  it("always reports checks that were never run, at every level", () => {
    for (const level of [0, 3]) {
      if (level === 3) {
        mkWorkflow(tmpDir, "release.yml", `
on: push
permissions:
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance
`);
      }
      const assessment = assessSLSA(tmpDir);
      expect(assessment.level).toBe(level);
      expect(assessment.notAssessed.length).toBeGreaterThan(0);
      expect(assessment.notAssessed.join(" ")).toContain("signature");
    }
  });

  it("names the job that produced an npm-native Level 3", () => {
    mkWorkflow(tmpDir, "release.yml", `
on: push
permissions:
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish --provenance
`);
    const assessment = assessSLSA(tmpDir);
    expect(assessment.level).toBe(3);
    expect(assessment.basis.join(" ")).toContain('job "publish" in release.yml');
  });
});

describe("verifySLSA", () => {
  it("should emit SLSA_LEVEL_0 finding for empty directory", () => {
    const findings = verifySLSA(tmpDir);
    expect(findings.some((f) => f.rule === "SLSA_LEVEL_0")).toBe(true);
    expect(findings.find((f) => f.rule === "SLSA_LEVEL_0")?.severity).toBe("info");
  });

  it("should emit SLSA_NO_PROVENANCE for level 1 project", () => {
    mkWorkflow(tmpDir, "ci.yml", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n");
    const findings = verifySLSA(tmpDir);
    expect(findings.some((f) => f.rule === "SLSA_NO_PROVENANCE")).toBe(true);
    expect(findings.find((f) => f.rule === "SLSA_NO_PROVENANCE")?.severity).toBe("low");
  });

  it("should emit SLSA_UNSIGNED_ARTIFACTS for level 2 project", () => {
    mkWorkflow(tmpDir, "release.yml", `
jobs:
  sign:
    steps:
      - uses: sigstore/cosign-action@v3
`);
    const findings = verifySLSA(tmpDir);
    expect(findings.some((f) => f.rule === "SLSA_UNSIGNED_ARTIFACTS")).toBe(true);
    expect(findings.find((f) => f.rule === "SLSA_UNSIGNED_ARTIFACTS")?.severity).toBe("info");
  });

  it("should emit no findings for level 3 project", () => {
    mkWorkflow(tmpDir, "release.yml", `
on:
  workflow_call:
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator@abc1234567890abcdef1234567890abcdef123456
`);
    const findings = verifySLSA(tmpDir);
    expect(findings).toHaveLength(0);
  });

  it("should include recommendation in SLSA_LEVEL_0 finding", () => {
    const findings = verifySLSA(tmpDir);
    const finding = findings.find((f) => f.rule === "SLSA_LEVEL_0");
    expect(finding?.recommendation).toContain("slsa-framework");
  });

  it("should emit SLSA_PROVENANCE_INVALID for a present-but-empty provenance file", () => {
    fs.writeFileSync(path.join(tmpDir, "provenance.json"), "{}");
    const findings = verifySLSA(tmpDir);
    const f = findings.find((x) => x.rule === "SLSA_PROVENANCE_INVALID");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("should NOT emit SLSA_PROVENANCE_INVALID for a valid provenance statement", () => {
    fs.writeFileSync(
      path.join(tmpDir, "provenance.json"),
      JSON.stringify({
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: "pkg", digest: { sha256: "b".repeat(64) } }],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: {},
      }),
    );
    const findings = verifySLSA(tmpDir);
    expect(findings.some((x) => x.rule === "SLSA_PROVENANCE_INVALID")).toBe(false);
  });

  it("should NOT flag a valid non-SLSA in-toto attestation (SBOM/SPDX predicate)", () => {
    // A legitimate SBOM attestation is a valid in-toto statement with a non-SLSA
    // predicate - it must not be reported as malformed provenance.
    fs.writeFileSync(
      path.join(tmpDir, "attestation.json"),
      JSON.stringify({
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: "pkg", digest: { sha256: "d".repeat(64) } }],
        predicateType: "https://cyclonedx.org/bom/v1.5",
        predicate: {},
      }),
    );
    const findings = verifySLSA(tmpDir);
    expect(findings.some((x) => x.rule === "SLSA_PROVENANCE_INVALID")).toBe(false);
    const res = parseAttestation(tmpDir);
    expect(res.kind).toBe("non-slsa-attestation");
    expect(res.valid).toBe(false);
  });

  it("should flag a SLSA statement with no digested subject as malformed", () => {
    fs.writeFileSync(
      path.join(tmpDir, "provenance.json"),
      JSON.stringify({
        _type: "https://in-toto.io/Statement/v1",
        subject: [],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: {},
      }),
    );
    const findings = verifySLSA(tmpDir);
    expect(findings.some((x) => x.rule === "SLSA_PROVENANCE_INVALID")).toBe(true);
  });

  it("should skip an oversized provenance file rather than read it (no memory DoS)", () => {
    // A pathological multi-MB provenance file is skipped, not read into memory.
    const big = path.join(tmpDir, "provenance.json");
    fs.writeFileSync(big, Buffer.alloc(6 * 1024 * 1024)); // > MAX_FILE_SIZE (5MB)
    const res = parseAttestation(tmpDir);
    expect(res.present).toBe(false); // skipped, not treated as a statement
  });

  it("parseAttestation validates a DSSE-wrapped statement", () => {
    const stmt = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "pkg", digest: { sha256: "c".repeat(64) } }],
      predicateType: "https://slsa.dev/provenance/v1",
      predicate: {},
    };
    const dsse = {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(stmt)).toString("base64"),
      signatures: [{ sig: "x" }],
    };
    fs.writeFileSync(path.join(tmpDir, "attestation.json"), JSON.stringify(dsse));
    const res = parseAttestation(tmpDir);
    expect(res.valid).toBe(true);
    expect(res.predicateType).toBe("https://slsa.dev/provenance/v1");
    expect(res.subjectCount).toBe(1);
  });

  it("should emit no findings for L3 npm-native path (--provenance + id-token: write)", () => {
    mkWorkflow(tmpDir, "ci.yml", `
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: npm publish --provenance
`);
    const findings = verifySLSA(tmpDir);
    expect(findings).toHaveLength(0);
  });

  it("should mention both L3 paths in the SLSA_UNSIGNED_ARTIFACTS recommendation", () => {
    mkWorkflow(tmpDir, "release.yml", `
jobs:
  sign:
    steps:
      - uses: sigstore/cosign-action@v3
`);
    const findings = verifySLSA(tmpDir);
    const finding = findings.find((f) => f.rule === "SLSA_UNSIGNED_ARTIFACTS");
    expect(finding?.recommendation).toContain("--provenance");
    expect(finding?.recommendation).toContain("id-token: write");
    expect(finding?.recommendation).toContain("slsa-framework/slsa-github-generator");
  });
});
