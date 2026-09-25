// release-provenance.mjs - fetch the published npm tarball and the SLSA
// provenance npm recorded for it, for attaching to the GitHub Release.
//
// Usage (the release job in .github/workflows/ci.yml):
//   node scripts/release-provenance.mjs <version> [outDir]
// writes
//   <outDir>/supply-chain-guard-<version>.tgz
//   <outDir>/supply-chain-guard-<version>.tgz.sigstore.json
//
// WHY THIS EXISTS. OpenSSF Scorecard's Signed-Releases check looks at the assets
// of the last five GitHub Releases for a signature file, and found none, because
// the signed provenance lived only on the npm registry. `npm publish --provenance`
// already produces exactly the right artefact: a Sigstore bundle, signed through
// this repository's GitHub OIDC identity, holding an SLSA v1 provenance statement
// whose subject is the tarball's sha512. Attaching THAT bundle next to THAT tarball
// adds no second signing identity and no new permission.
//
// WHAT IT CHECKS, all failing closed:
//   * the downloaded tarball's sha512 equals the registry's `dist.integrity`;
//   * an attestation with predicateType SLSA provenance v1 exists;
//   * the DSSE payload inside that bundle declares the same predicate type;
//   * its subject names pkg:npm/supply-chain-guard@<version> with that sha512.
// A mismatched pair would read as "signed" to Scorecard and to a person, and
// verify as nothing, which is worse than no signature.
//
// WHAT IT DOES NOT CHECK: the Sigstore signature itself. That needs the Sigstore
// trust root and is what a consumer verifies:
//   gh attestation verify supply-chain-guard-<v>.tgz \
//     --bundle supply-chain-guard-<v>.tgz.sigstore.json \
//     --repo homeofe/supply-chain-guard --digest-alg sha512
// Run against the real v6.2.5 assets on 2026-09-25: it verified an SLSA v1
// statement signed by .github/workflows/ci.yml@refs/tags/v6.2.5 with a
// transparency-log entry, and failed on a copy of the tarball with one byte
// appended. `npm audit signatures` checks the same thing against the registry.

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PACKAGE = "supply-chain-guard";
export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
const REGISTRY = "https://registry.npmjs.org";

const ATTEMPTS = 6;
const sleep = (ms) => (ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

/**
 * GET with a bounded wait for registry propagation. The release job runs
 * seconds after `npm publish`, and the registry and its CDN can answer 404 for
 * a short while. A request that throws (a reset connection, a failed DNS
 * lookup) is the same transient state and is retried the same way; it used to
 * fail the release job on the first try. Six tries is about a minute at the
 * default delay; anything longer is an outage, and the job should say so
 * rather than hang.
 */
async function get(url, { fetchImpl, retryDelayMs, attempts = ATTEMPTS }) {
  let last = "";
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetchImpl(url);
      if (res.ok) return res;
      last = `status ${res.status}`;
    } catch (err) {
      last = `error: ${err instanceof Error ? err.message : err}`;
    }
    if (i < attempts - 1) await sleep(retryDelayMs);
  }
  throw new Error(`GET ${url} failed after ${attempts} attempts (last ${last})`);
}

const sha512 = (buf) => createHash("sha512").update(buf);

export async function fetchReleaseProvenance(
  version,
  { outDir = ".", fetchImpl = fetch, retryDelayMs = 10_000 } = {},
) {
  if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) throw new Error(`not a release version: ${version}`);
  const opts = { fetchImpl, retryDelayMs };

  // The version document and its attestations are read together, and their
  // ABSENCE is retried like a 404: right after publish a cached copy of the
  // document can lack dist.attestations, or the list can lack the SLSA entry.
  // Nothing that is present is retried. A wrong integrity, digest, name or
  // predicate is an answer, not a delay, and fails at once below.
  let meta;
  let slsa;
  for (let i = 0; ; i++) {
    meta = await (await get(`${REGISTRY}/${PACKAGE}/${version}`, opts)).json();
    const attestationsUrl = meta?.dist?.attestations?.url;
    let missing = `registry reports no attestations for ${PACKAGE}@${version}`;
    if (typeof attestationsUrl === "string") {
      const { attestations } = await (await get(attestationsUrl, opts)).json();
      slsa = (attestations ?? []).find((a) => a?.predicateType === SLSA_PROVENANCE_V1);
      if (slsa?.bundle?.dsseEnvelope?.payload) break;
      missing = `npm recorded no SLSA provenance bundle for ${PACKAGE}@${version}`;
    }
    if (i >= ATTEMPTS - 1) throw new Error(`${missing} (${ATTEMPTS} reads)`);
    await sleep(retryDelayMs);
  }

  const integrity = meta?.dist?.integrity;
  if (typeof integrity !== "string" || !integrity.startsWith("sha512-")) {
    throw new Error(`registry reports no sha512 integrity for ${PACKAGE}@${version}: ${integrity}`);
  }

  const tarball = Buffer.from(await (await get(meta.dist.tarball, opts)).arrayBuffer());
  if (`sha512-${sha512(tarball).digest("base64")}` !== integrity) {
    throw new Error(`downloaded tarball does not match the registry integrity ${integrity}`);
  }
  const digestHex = sha512(tarball).digest("hex");

  const stmt = JSON.parse(Buffer.from(slsa.bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  if (stmt.predicateType !== SLSA_PROVENANCE_V1) {
    throw new Error(`bundle filed as SLSA provenance declares predicate ${stmt.predicateType}`);
  }
  const expectedName = `pkg:npm/${PACKAGE}@${version}`;
  const matches = (stmt.subject ?? []).some(
    (s) => s?.name === expectedName && s?.digest?.sha512 === digestHex,
  );
  if (!matches) {
    throw new Error(`provenance subject does not name ${expectedName} with the tarball's sha512`);
  }

  mkdirSync(outDir, { recursive: true });
  const tgz = join(outDir, `${PACKAGE}-${version}.tgz`);
  writeFileSync(tgz, tarball);
  writeFileSync(`${tgz}.sigstore.json`, JSON.stringify(slsa.bundle));
  return { files: [tgz, `${tgz}.sigstore.json`], sha512: digestHex };
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  const [version, outDir] = process.argv.slice(2);
  try {
    const { files, sha512: hex } = await fetchReleaseProvenance(version, { outDir: outDir ?? "." });
    console.log(`release provenance OK: ${files.join(", ")} (sha512 ${hex.slice(0, 16)}...)`);
  } catch (err) {
    console.error(`::error title=Release provenance::${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}
