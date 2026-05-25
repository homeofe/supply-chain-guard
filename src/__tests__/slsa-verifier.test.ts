import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { getSLSALevel, verifySLSA } from "../slsa-verifier.js";

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

  it("should return 3 when slsa-github-generator SHA + attestation file", () => {
    mkWorkflow(tmpDir, "release.yml", `
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator@abc1234567890abcdef1234567890abcdef123456
`);
    fs.writeFileSync(path.join(tmpDir, "provenance.json"), "{}");
    expect(getSLSALevel(tmpDir)).toBe(3);
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

  it("should treat --provenance + id-token:write split across two workflow files as L3", () => {
    // Detection scans the concatenated content of all workflows in
    // .github/workflows/, mirroring how reviewers read a repo's CI surface.
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
    expect(getSLSALevel(tmpDir)).toBe(3);
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
