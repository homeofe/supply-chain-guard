import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";

import { fetchReleaseProvenance, SLSA_PROVENANCE_V1 } from "../../scripts/release-provenance.mjs";

// The GitHub Release carries the npm tarball and the Sigstore bundle of the SLSA
// provenance npm recorded when it was published. The script must never attach a
// bundle that does not describe the tarball beside it: a mismatched pair would
// read as "signed" to OpenSSF Scorecard and to any human, and verify as nothing.
// So every check below fails closed, and each one has a test that goes red when
// that check is cut.

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "scg-provenance-"));
  dirs.push(d);
  return d;
};

const VERSION = "9.9.9";
const TARBALL = Buffer.from("not really a tarball, but bytes with a digest");
const SHA512_HEX = createHash("sha512").update(TARBALL).digest("hex");
const INTEGRITY = `sha512-${createHash("sha512").update(TARBALL).digest("base64")}`;

const statement = (overrides: Record<string, unknown> = {}) => ({
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: `pkg:npm/supply-chain-guard@${VERSION}`, digest: { sha512: SHA512_HEX } }],
  predicateType: SLSA_PROVENANCE_V1,
  predicate: {},
  ...overrides,
});
const bundleFor = (stmt: unknown) => ({
  mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
  verificationMaterial: { certificate: { rawBytes: "Zm9v" } },
  dsseEnvelope: {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(stmt)).toString("base64"),
    signatures: [{ sig: "c2ln" }],
  },
});

interface Fixture {
  integrity?: string;
  tarball?: Buffer;
  attestations?: unknown[];
  failFirst?: number;
}

/** A fake registry. `failFirst` answers 404 that many times before the real data. */
function registry(f: Fixture = {}) {
  let failures = f.failFirst ?? 0;
  const calls: string[] = [];
  const fetchImpl = async (url: string) => {
    calls.push(url);
    if (failures > 0) {
      failures--;
      return new Response("not yet", { status: 404 });
    }
    if (url === `https://registry.npmjs.org/supply-chain-guard/${VERSION}`) {
      return Response.json({
        version: VERSION,
        dist: {
          integrity: f.integrity ?? INTEGRITY,
          tarball: `https://registry.npmjs.org/supply-chain-guard/-/supply-chain-guard-${VERSION}.tgz`,
          attestations: { url: `https://registry.npmjs.org/-/npm/v1/attestations/supply-chain-guard@${VERSION}` },
        },
      });
    }
    if (url.endsWith(`supply-chain-guard-${VERSION}.tgz`)) {
      return new Response(f.tarball ?? TARBALL);
    }
    if (url.endsWith(`attestations/supply-chain-guard@${VERSION}`)) {
      return Response.json({
        attestations: f.attestations ?? [
          { predicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1", bundle: bundleFor({}) },
          { predicateType: SLSA_PROVENANCE_V1, bundle: bundleFor(statement()) },
        ],
      });
    }
    return new Response("unexpected", { status: 500 });
  };
  return { fetchImpl, calls };
}

const run = (f?: Fixture) => {
  const outDir = tmp();
  const { fetchImpl, calls } = registry(f);
  const promise = fetchReleaseProvenance(VERSION, { outDir, fetchImpl, retryDelayMs: 0 });
  return { promise, outDir, calls };
};

describe("release provenance", () => {
  it("writes the tarball and the SLSA provenance bundle when everything matches", async () => {
    const { promise, outDir } = run();
    const result = await promise;
    const tgz = path.join(outDir, `supply-chain-guard-${VERSION}.tgz`);
    expect(result.files).toEqual([tgz, `${tgz}.sigstore.json`]);
    expect(fs.readFileSync(tgz).equals(TARBALL)).toBe(true);
    const written = JSON.parse(fs.readFileSync(`${tgz}.sigstore.json`, "utf8"));
    expect(written).toEqual(bundleFor(statement()));
  });

  it("refuses a tarball whose sha512 differs from the registry's integrity", async () => {
    await expect(run({ tarball: Buffer.from("tampered") }).promise).rejects.toThrow(/integrity/);
  });

  it("refuses when the registry reports no sha512 integrity at all", async () => {
    // Its own message, not only "does not match": a registry that stopped
    // reporting sha512 needs a different response from a tampered tarball.
    // Matching /integrity/ alone let this check be cut with the suite green,
    // because the comparison below it rejects the same input.
    await expect(run({ integrity: "sha1-abc" }).promise).rejects.toThrow(/no sha512 integrity/);
  });

  it("refuses a provenance statement about a different digest", async () => {
    const other = statement({
      subject: [{ name: `pkg:npm/supply-chain-guard@${VERSION}`, digest: { sha512: "00".repeat(64) } }],
    });
    await expect(
      run({ attestations: [{ predicateType: SLSA_PROVENANCE_V1, bundle: bundleFor(other) }] }).promise,
    ).rejects.toThrow(/subject/);
  });

  it("refuses a provenance statement about another package or version", async () => {
    const other = statement({
      subject: [{ name: "pkg:npm/supply-chain-guard@9.9.8", digest: { sha512: SHA512_HEX } }],
    });
    await expect(
      run({ attestations: [{ predicateType: SLSA_PROVENANCE_V1, bundle: bundleFor(other) }] }).promise,
    ).rejects.toThrow(/subject/);
  });

  it("refuses when npm recorded no SLSA provenance, even if another attestation exists", async () => {
    await expect(
      run({
        attestations: [
          { predicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1", bundle: bundleFor(statement()) },
        ],
      }).promise,
    ).rejects.toThrow(/SLSA provenance/);
  });

  it("refuses a bundle whose payload claims a different predicate type than it is filed under", async () => {
    const mislabelled = statement({ predicateType: "https://example.invalid/other" });
    await expect(
      run({ attestations: [{ predicateType: SLSA_PROVENANCE_V1, bundle: bundleFor(mislabelled) }] }).promise,
    ).rejects.toThrow(/predicate/);
  });

  it("refuses a version that is not an exact release", async () => {
    await expect(
      fetchReleaseProvenance("latest", { outDir: tmp(), fetchImpl: registry().fetchImpl, retryDelayMs: 0 }),
    ).rejects.toThrow(/release version/);
  });

  it("waits for the registry to catch up, a bounded number of times", async () => {
    const ok = run({ failFirst: 2 });
    await expect(ok.promise).resolves.toBeDefined();
    const gives_up = run({ failFirst: 50 });
    await expect(gives_up.promise).rejects.toThrow(/404/);
    expect(gives_up.calls.length).toBeLessThan(50);
  });
});
