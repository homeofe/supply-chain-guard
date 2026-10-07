/**
 * Integrity and provenance hardening: lockfile SRI parsing, lookalike registry
 * hosts, governance on malformed / v1 lockfiles, SLSA attestation checks and
 * the npm dist integrity downgrade.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { scan } from "../scanner.js";
import { checkDependencyGovernance, isTrustedResolved } from "../dependency-governance.js";
import { verifySLSA } from "../slsa-verifier.js";
import { verifyNpmDistIntegrity } from "../npm-scanner.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-integrity-hardening-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeLock(packages: Record<string, unknown>): void {
  fs.writeFileSync(
    path.join(tmpDir, "package.json"),
    JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { dep: "1.0.0" } }),
  );
  fs.writeFileSync(
    path.join(tmpDir, "package-lock.json"),
    JSON.stringify({
      name: "demo",
      lockfileVersion: 3,
      packages: { "": { version: "1.0.0" }, ...packages },
    }),
  );
}

async function lockRules(): Promise<string[]> {
  const report = await scan({ target: tmpDir, noHistory: true });
  return report.findings.map((f) => f.rule);
}

const GOOD_SHA512 = `sha512-${Buffer.alloc(64, 9).toString("base64")}`;
const GOOD_SHA1 = `sha1-${Buffer.alloc(20, 9).toString("base64")}`;
const REGISTRY_TGZ = "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz";

describe("F21: lockfile integrity is parsed, not prefix-tested", () => {
  it("flags a sha512 token whose decoded length is wrong", async () => {
    writeLock({
      "node_modules/dep": {
        version: "1.0.0",
        resolved: REGISTRY_TGZ,
        integrity: "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    });
    expect(await lockRules()).toContain("LOCKFILE_INVALID_INTEGRITY");
  });

  it("flags a sha1 token that is not 20 bytes", async () => {
    writeLock({
      "node_modules/dep": {
        version: "1.0.0",
        resolved: REGISTRY_TGZ,
        integrity: "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    });
    expect(await lockRules()).toContain("LOCKFILE_INVALID_INTEGRITY");
  });

  it("flags a sha1-only entry as weak, low severity", async () => {
    writeLock({
      "node_modules/dep": { version: "1.0.0", resolved: REGISTRY_TGZ, integrity: GOOD_SHA1 },
    });
    const report = await scan({ target: tmpDir, noHistory: true });
    const weak = report.findings.find((f) => f.rule === "LOCKFILE_WEAK_INTEGRITY");
    expect(weak?.severity).toBe("low");
    expect(report.findings.map((f) => f.rule)).not.toContain("LOCKFILE_INVALID_INTEGRITY");
  });

  it("stays clean for a real sha512, and for sha1 next to sha512", async () => {
    writeLock({
      "node_modules/dep": { version: "1.0.0", resolved: REGISTRY_TGZ, integrity: GOOD_SHA512 },
    });
    let rules = await lockRules();
    expect(rules).not.toContain("LOCKFILE_INVALID_INTEGRITY");
    expect(rules).not.toContain("LOCKFILE_WEAK_INTEGRITY");
    expect(rules).not.toContain("LOCKFILE_SHORT_INTEGRITY");

    writeLock({
      "node_modules/dep": {
        version: "1.0.0",
        resolved: REGISTRY_TGZ,
        integrity: `${GOOD_SHA1} ${GOOD_SHA512}`,
      },
    });
    rules = await lockRules();
    expect(rules).not.toContain("LOCKFILE_INVALID_INTEGRITY");
    expect(rules).not.toContain("LOCKFILE_WEAK_INTEGRITY");
  });
});

describe("F31: lookalike registry hosts are graded high", () => {
  for (const resolved of [
    "https://registry.npmjs.org.attacker.example/dep/-/dep-1.0.0.tgz",
    "https://registry-npmjs.org/dep/-/dep-1.0.0.tgz",
    "https://registry.npmjs.org@attacker.example/dep/-/dep-1.0.0.tgz",
    "https://registry.npmjs.org:8443/dep/-/dep-1.0.0.tgz",
  ]) {
    it(`grades ${resolved.replace(/\./g, "[.]")} high, once`, async () => {
      writeLock({
        "node_modules/dep": { version: "1.0.0", resolved, integrity: GOOD_SHA512 },
      });
      const report = await scan({ target: tmpDir, noHistory: true });
      const hits = report.findings.filter((f) => f.rule === "DEPENDENCY_UNTRUSTED_SOURCE");
      expect(hits).toHaveLength(1);
      expect(hits[0]!.severity).toBe("high");
      expect(report.findings.map((f) => f.rule)).not.toContain("LOCKFILE_NONREGISTRY_RESOLVED");
    });
  }

  it("keeps an ordinary private registry at low severity and the real one clean", async () => {
    writeLock({
      "node_modules/dep": {
        version: "1.0.0",
        resolved: "https://npm.corp.example/dep/-/dep-1.0.0.tgz",
        integrity: GOOD_SHA512,
      },
    });
    const privateRules = await lockRules();
    expect(privateRules).toContain("LOCKFILE_NONREGISTRY_RESOLVED");
    expect(privateRules).not.toContain("DEPENDENCY_UNTRUSTED_SOURCE");

    writeLock({
      "node_modules/dep": { version: "1.0.0", resolved: REGISTRY_TGZ, integrity: GOOD_SHA512 },
    });
    const cleanRules = await lockRules();
    expect(cleanRules).not.toContain("LOCKFILE_NONREGISTRY_RESOLVED");
    expect(cleanRules).not.toContain("DEPENDENCY_UNTRUSTED_SOURCE");
  });
});

describe("F32: governance tolerates malformed data and reads v1 dependencies", () => {
  it("does not throw on a non-string resolved", () => {
    expect(isTrustedResolved(123)).toBe(false);
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/a": { resolved: 123 }, "node_modules/b": { resolved: ["x"] } },
    });
    expect(() => checkDependencyGovernance({}, lock, "package-lock.json")).not.toThrow();
    expect(checkDependencyGovernance({}, lock, "package-lock.json")).toHaveLength(2);
  });

  it("walks lockfile v1 dependencies recursively", () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        a: {
          version: "1.0.0",
          resolved: REGISTRY_TGZ,
          dependencies: { nested: { version: "1.0.0", resolved: "https://evil.example/a.tgz" } },
        },
      },
    });
    const findings = checkDependencyGovernance({}, lock, "package-lock.json");
    expect(findings.map((f) => f.rule)).toEqual(["DEPENDENCY_UNTRUSTED_SOURCE"]);
  });

  it("does not double-report a v2 lockfile that lists a package twice", () => {
    const entry = { version: "1.0.0", resolved: "https://evil.example/a.tgz" };
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: { "node_modules/a": entry },
      dependencies: { a: entry },
    });
    expect(checkDependencyGovernance({}, lock, "package-lock.json")).toHaveLength(1);
  });

  it("stays clean for registry and file: sources", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/a": { resolved: REGISTRY_TGZ },
        "node_modules/b": { resolved: "file:../b" },
      },
    });
    expect(checkDependencyGovernance({}, lock, "package-lock.json")).toEqual([]);
  });
});

describe("F33: SLSA attestation checks", () => {
  const GENERATOR_WORKFLOW = `
on:
  workflow_call:
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator@abc1234567890abcdef1234567890abcdef123456
`;

  function writeWorkflow(): void {
    const dir = path.join(tmpDir, ".github", "workflows");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "release.yml"), GENERATOR_WORKFLOW);
  }

  function envelope(subject: unknown): string {
    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      predicateType: "https://slsa.dev/provenance/v1",
      subject: [subject],
      predicate: { runDetails: { builder: { id: "https://foreign.example/builder" } } },
    };
    return JSON.stringify({
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
      signatures: [{ sig: "AAAA" }],
    });
  }

  it("never reports level 3 from workflow text without saying nothing was read", () => {
    writeWorkflow();
    const rules = verifySLSA(tmpDir).map((f) => f.rule);
    expect(rules).toContain("SLSA_SIGNATURE_NOT_VERIFIED");
  });

  it("finds multiple.intoto.jsonl and always emits SLSA_SIGNATURE_NOT_VERIFIED for it", () => {
    writeWorkflow();
    fs.writeFileSync(
      path.join(tmpDir, "multiple.intoto.jsonl"),
      envelope({ name: "other-artifact", digest: { sha256: "a".repeat(64) } }),
    );
    const findings = verifySLSA(tmpDir);
    const note = findings.find((f) => f.rule === "SLSA_SIGNATURE_NOT_VERIFIED");
    expect(note?.description).toContain("multiple.intoto.jsonl");
  });

  it("rejects a digest of the wrong length as not usable", () => {
    writeWorkflow();
    fs.writeFileSync(
      path.join(tmpDir, "provenance.intoto.jsonl"),
      envelope({ name: "other-artifact", digest: { sha256: "a" } }),
    );
    const rules = verifySLSA(tmpDir).map((f) => f.rule);
    expect(rules).toContain("SLSA_PROVENANCE_INVALID");
  });

  it("flags a subject whose digest does not match the artefact in the tree", () => {
    writeWorkflow();
    fs.writeFileSync(path.join(tmpDir, "pkg.tgz"), "real bytes");
    fs.writeFileSync(
      path.join(tmpDir, "provenance.intoto.jsonl"),
      envelope({ name: "pkg.tgz", digest: { sha256: "b".repeat(64) } }),
    );
    const finding = verifySLSA(tmpDir).find((f) => f.rule === "SLSA_SUBJECT_DIGEST_MISMATCH");
    expect(finding?.severity).toBe("high");
  });

  it("stays quiet about the subject when the digest matches", () => {
    writeWorkflow();
    fs.writeFileSync(path.join(tmpDir, "pkg.tgz"), "real bytes");
    const sha256 = createHash("sha256").update("real bytes").digest("hex");
    fs.writeFileSync(
      path.join(tmpDir, "provenance.intoto.jsonl"),
      envelope({ name: "pkg.tgz", digest: { sha256 } }),
    );
    expect(verifySLSA(tmpDir).map((f) => f.rule)).not.toContain("SLSA_SUBJECT_DIGEST_MISMATCH");
  });

  it("reports an oversized attestation file as a coverage finding", () => {
    writeWorkflow();
    fs.writeFileSync(path.join(tmpDir, "provenance.json"), Buffer.alloc(6 * 1024 * 1024, 0x20));
    const rules = verifySLSA(tmpDir).map((f) => f.rule);
    expect(rules).toContain("FILE_TOO_LARGE_SKIPPED");
  });
});

describe("F34: npm dist integrity downgrade", () => {
  const payload = Buffer.from("npm tarball fixture");
  const sha512 = createHash("sha512").update(payload).digest("base64");
  const sha256 = createHash("sha256").update(payload).digest("base64");
  const sha1 = createHash("sha1").update(payload).digest("hex");

  function tarball(): string {
    const p = path.join(tmpDir, "package.tgz");
    fs.writeFileSync(p, payload);
    return p;
  }

  it("fails when a strong token is malformed even if a weaker one is correct", async () => {
    const truncated = `sha512-${sha512.slice(0, 40)}`;
    expect(await verifyNpmDistIntegrity(tarball(), { integrity: `${truncated} sha256-${sha256}` })).toBe(false);
  });

  it("fails on a present non-string integrity instead of trusting shasum", async () => {
    const p = tarball();
    const arrayIntegrity = [`sha512-${sha512}`] as unknown as string;
    expect(await verifyNpmDistIntegrity(p, { integrity: arrayIntegrity, shasum: sha1 })).toBe(false);
    expect(await verifyNpmDistIntegrity(p, { integrity: 5 as unknown as string, shasum: sha1 })).toBe(false);
  });

  it("still accepts correct digests and an absent integrity with a correct shasum", async () => {
    const p = tarball();
    expect(await verifyNpmDistIntegrity(p, { integrity: `sha256-${sha256} sha512-${sha512}` })).toBe(true);
    expect(await verifyNpmDistIntegrity(p, { shasum: sha1 })).toBe(true);
  });
});
