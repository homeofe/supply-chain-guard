// verify-action-install.mjs - refuse to run a scanner the Action cannot prove
// this repository built.
//
// Usage (the "Install supply-chain-guard" step of action.yml, after
// `npm install` into a throwaway project and
// `npm audit signatures --json --include-attestations` over it):
//   node scripts/verify-action-install.mjs
// with every input in the environment:
//   SCG_INSTALL_DIR              the throwaway project (package-lock.json, node_modules)
//   SCG_AUDIT_JSON               the saved `npm audit signatures` JSON
//   SCG_NPM_VERSION              `npm --version`
//   SCG_VERSION                  the release the Action pins
//   SCG_EXPECTED_REPOSITORY      owner/name of the repository that must have built it
//   SCG_EXPECTED_REPOSITORY_ID   that repository's numeric GitHub id
//   SCG_EXPECTED_WORKFLOW        the workflow file that publishes it
// Exit 0 and one summary line when every check holds; exit 1 with an ::error
// annotation naming the first check that failed otherwise.
//
// WHY. The Action used to run `npm install -g supply-chain-guard@<version>`:
// pinned by version, not by content. A registry or CDN response that served
// other bytes under that version would have run as the scanner, with the
// consumer's checkout and token in reach. Pinning a tarball hash in action.yml
// is not possible, because action.yml ships inside the tarball whose hash it
// would have to contain.
//
// WHAT CARRIES THE WEIGHT. The package is published with npm provenance: a
// Sigstore-signed SLSA statement whose certificate Fulcio issued to one GitHub
// Actions workflow run. `npm audit signatures` verifies the registry signature
// and that bundle cryptographically (certificate chain to the Sigstore root,
// transparency-log entry, DSSE signature, subject digest equal to the
// registry's integrity). What it does NOT do is ask WHO signed: a valid bundle
// from any repository's workflow passes, and a package with no attestation at
// all passes too, silently. This script closes both, reading the bundles npm
// just verified (`--include-attestations` prints the exact objects it checked,
// so there is no second fetch that could return different bytes):
//   * an SLSA provenance attestation exists for exactly this name, version and
//     install location, and npm reported nothing invalid or missing;
//   * the signing certificate's identity is this repository: the Fulcio issuer
//     is GitHub Actions, the source repository URI and its numeric id match,
//     the build ref is the release tag, and the SAN is the publishing
//     workflow at that tag;
//   * the signed statement names the same repository, workflow and tag, and
//     its subject digest equals the integrity of the tarball npm installed
//     (package-lock.json), so the attestation describes the bytes on disk;
//   * the installed package.json is that name and version.
// The numeric repository id is what survives a rename and does not survive a
// delete-and-recreate under the same name, which is the one way a stranger
// could otherwise come to own "owner/name".
//
// Requires npm 11.12.0 or later (bundled with Node 24.15.0 or later) for
// `--include-attestations`. An older npm prints no attestation details, and
// that fails closed here with a message saying so.

import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PACKAGE = "supply-chain-guard";
export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
export const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
export const PUBLIC_REGISTRY = "https://registry.npmjs.org";
export const MIN_NPM_VERSION = [11, 12, 0];

// Fulcio certificate extensions (sigstore/fulcio docs/oid-info.md).
const OID_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1";
const OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
const OID_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12";
const OID_SOURCE_REPOSITORY_REF = "1.3.6.1.4.1.57264.1.14";
const OID_SOURCE_REPOSITORY_ID = "1.3.6.1.4.1.57264.1.15";

export class InstallVerificationError extends Error {}

function fail(message) {
  throw new InstallVerificationError(message);
}

// ---------------------------------------------------------------------------
// Minimal DER reader: enough to list a certificate's extensions. Node's
// X509Certificate exposes the SAN but not arbitrary extensions.
// ---------------------------------------------------------------------------

function readTlv(der, offset, limit) {
  if (offset + 2 > limit) fail("certificate is truncated");
  const tag = der[offset];
  let length = der[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const octets = length & 0x7f;
    if (octets === 0 || octets > 4 || offset + 2 + octets > limit) fail("certificate has an unsupported length");
    length = 0;
    for (let i = 0; i < octets; i++) length = length * 256 + der[offset + 2 + i];
    header += octets;
  }
  const start = offset + header;
  const end = start + length;
  if (end > limit) fail("certificate is truncated");
  return { tag, start, end };
}

function children(der, start, end) {
  const out = [];
  for (let offset = start; offset < end; ) {
    const tlv = readTlv(der, offset, end);
    out.push(tlv);
    offset = tlv.end;
  }
  return out;
}

function oidString(bytes) {
  if (bytes.length === 0) return "";
  const arcs = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  return arcs.join(".");
}

/** Map of extension OID to its raw extnValue contents. */
export function certificateExtensions(der) {
  const certificate = readTlv(der, 0, der.length);
  const [tbs] = children(der, certificate.start, certificate.end);
  if (!tbs) fail("certificate has no body");
  const extensions = new Map();
  for (const field of children(der, tbs.start, tbs.end)) {
    if (field.tag !== 0xa3) continue;
    const [sequence] = children(der, field.start, field.end);
    for (const extension of children(der, sequence.start, sequence.end)) {
      const parts = children(der, extension.start, extension.end);
      const id = parts[0];
      const value = parts[parts.length - 1];
      if (!id || id.tag !== 0x06 || !value || value.tag !== 0x04) fail("certificate extension is malformed");
      extensions.set(oidString(der.subarray(id.start, id.end)), der.subarray(value.start, value.end));
    }
  }
  return extensions;
}

/** Fulcio string extension: DER UTF8String (v2 OIDs) or raw bytes (1.1). */
function extensionText(value) {
  if (value === undefined) return undefined;
  if (value.length >= 2 && value[0] === 0x0c) {
    const inner = readTlv(value, 0, value.length);
    return Buffer.from(value.subarray(inner.start, inner.end)).toString("utf8");
  }
  return Buffer.from(value).toString("utf8");
}

/** The signing identity recorded in a Sigstore bundle's leaf certificate. */
export function certificateIdentity(bundle) {
  const material = bundle?.verificationMaterial ?? {};
  const raw = material.certificate?.rawBytes ?? material.x509CertificateChain?.certificates?.[0]?.rawBytes;
  if (typeof raw !== "string") fail("the provenance bundle carries no signing certificate");
  const der = Buffer.from(raw, "base64");
  let san;
  try {
    san = new X509Certificate(der).subjectAltName ?? "";
  } catch {
    fail("the provenance signing certificate does not parse");
  }
  const extensions = certificateExtensions(der);
  return {
    san,
    issuer: extensionText(extensions.get(OID_ISSUER_V2)) ?? extensionText(extensions.get(OID_ISSUER_V1)),
    sourceRepository: extensionText(extensions.get(OID_SOURCE_REPOSITORY_URI)),
    sourceRepositoryRef: extensionText(extensions.get(OID_SOURCE_REPOSITORY_REF)),
    sourceRepositoryId: extensionText(extensions.get(OID_SOURCE_REPOSITORY_ID)),
  };
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

function npmVersionAtLeast(version, minimum) {
  const parts = /^(\d+)\.(\d+)\.(\d+)/.exec(version ?? "");
  if (!parts) return false;
  for (let i = 0; i < 3; i++) {
    const have = Number(parts[i + 1]);
    if (have !== minimum[i]) return have > minimum[i];
  }
  return true;
}

function sha512Hex(integrity) {
  const entry = String(integrity ?? "")
    .split(/\s+/)
    .find((candidate) => candidate.startsWith("sha512-"));
  if (!entry) fail(`the lockfile records no sha512 integrity for ${PACKAGE}`);
  return Buffer.from(entry.slice("sha512-".length), "base64").toString("hex");
}

/**
 * Verify one install. Pure: every input is passed in, so each check can be
 * driven by a test. Throws InstallVerificationError naming the first failure.
 */
export function verifyScannerInstall({
  lockfile,
  installedManifest,
  audit,
  npmVersion,
  version,
  repository,
  repositoryId,
  workflow,
}) {
  for (const [name, value] of Object.entries({ version, repository, repositoryId, workflow })) {
    if (typeof value !== "string" || value === "") fail(`no expected ${name} was configured`);
  }
  if (!npmVersionAtLeast(npmVersion, MIN_NPM_VERSION)) {
    fail(
      `npm ${npmVersion || "(unknown)"} cannot report the attestations it verified ` +
        `(npm ${MIN_NPM_VERSION.join(".")} or later is needed, bundled with Node 24.15.0 or later), ` +
        "so the scanner's provenance cannot be checked and it will not be run",
    );
  }
  const repositoryUri = `https://github.com/${repository}`;
  const tag = `refs/tags/v${version}`;
  const purl = `pkg:npm/${PACKAGE}@${version}`;

  // What npm installed, and from where.
  const locked = lockfile?.packages?.[`node_modules/${PACKAGE}`];
  if (!locked) fail(`package-lock.json has no entry for ${PACKAGE}`);
  if (locked.version !== version) fail(`package-lock.json resolved ${PACKAGE}@${locked.version}, not ${version}`);
  const tarball = `${PUBLIC_REGISTRY}/${PACKAGE}/-/${PACKAGE}-${version}.tgz`;
  if (locked.resolved !== tarball) fail(`${PACKAGE} was resolved from ${locked.resolved}, not ${tarball}`);
  const installedDigest = sha512Hex(locked.integrity);
  if (installedManifest?.name !== PACKAGE || installedManifest?.version !== version) {
    fail(`the installed package is ${installedManifest?.name}@${installedManifest?.version}, not ${PACKAGE}@${version}`);
  }

  // What npm verified.
  if (!audit || !Array.isArray(audit.invalid) || !Array.isArray(audit.missing)) {
    fail("npm audit signatures produced no report");
  }
  if (audit.invalid.length > 0 || audit.missing.length > 0) {
    const names = [...audit.invalid, ...audit.missing].map((entry) => `${entry.name}@${entry.version}`);
    fail(`npm audit signatures reported invalid or missing signatures: ${names.join(", ")}`);
  }
  if (!Array.isArray(audit.verified)) {
    fail(
      "npm audit signatures reported no attestation details (--include-attestations was not honoured), " +
        "so the scanner's provenance cannot be checked",
    );
  }
  const entry = audit.verified.find(
    (candidate) =>
      candidate?.name === PACKAGE &&
      candidate?.version === version &&
      candidate?.location === `node_modules/${PACKAGE}`,
  );
  if (!entry) {
    fail(
      `npm verified no attestation for ${PACKAGE}@${version}. Every release is published with provenance, ` +
        "so an install without one is not a release this repository built",
    );
  }
  const provenance = (entry.attestationBundles ?? []).find((bundle) => bundle?.predicateType === SLSA_PROVENANCE_V1);
  if (!provenance?.bundle?.dsseEnvelope?.payload) {
    fail(`npm verified no SLSA provenance attestation for ${PACKAGE}@${version}`);
  }

  // Who signed it. Checked before the statement: the statement is text the
  // signer chose, the certificate is what Fulcio attests about the signer.
  const identity = certificateIdentity(provenance.bundle);
  const expectedSan = `URI:${repositoryUri}/${workflow}@${tag}`;
  if (identity.issuer !== GITHUB_ACTIONS_ISSUER) {
    fail(`the provenance was not issued to a GitHub Actions workflow (issuer ${identity.issuer ?? "absent"})`);
  }
  if (identity.sourceRepository !== repositoryUri) {
    fail(`the provenance was built in ${identity.sourceRepository ?? "an unnamed repository"}, not ${repositoryUri}`);
  }
  if (identity.sourceRepositoryId !== repositoryId) {
    fail(
      `the provenance was built in repository id ${identity.sourceRepositoryId ?? "(absent)"}, not ${repositoryId}: ` +
        `${repository} is not the repository that publishes this package`,
    );
  }
  if (identity.sourceRepositoryRef !== tag) {
    fail(`the provenance was built from ${identity.sourceRepositoryRef ?? "an unnamed ref"}, not ${tag}`);
  }
  if (identity.san !== expectedSan) {
    fail(`the provenance was signed by ${identity.san || "(no identity)"}, not ${expectedSan}`);
  }

  // What was signed.
  let statement;
  try {
    statement = JSON.parse(Buffer.from(provenance.bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  } catch {
    fail("the provenance statement does not parse");
  }
  if (statement?.predicateType !== SLSA_PROVENANCE_V1) {
    fail(`the provenance statement declares predicate ${statement?.predicateType}`);
  }
  const subjectMatches = (statement.subject ?? []).some(
    (subject) => subject?.name === purl && subject?.digest?.sha512 === installedDigest,
  );
  if (!subjectMatches) {
    fail(`the provenance does not describe the installed tarball (${purl} with the sha512 in package-lock.json)`);
  }
  const workflowParams = statement.predicate?.buildDefinition?.externalParameters?.workflow ?? {};
  if (workflowParams.repository !== repositoryUri || workflowParams.ref !== tag || workflowParams.path !== workflow) {
    fail(
      `the provenance statement names ${workflowParams.repository}/${workflowParams.path}@${workflowParams.ref}, ` +
        `not ${repositoryUri}/${workflow}@${tag}`,
    );
  }

  return {
    summary:
      `${PACKAGE}@${version}: registry signature and SLSA provenance verified by npm ${npmVersion}; ` +
      `built by ${repositoryUri}/${workflow}@${tag} (repository id ${repositoryId}); ` +
      `sha512 ${installedDigest.slice(0, 16)}... matches the installed tarball`,
  };
}

function readJson(file, label) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${label} could not be read: ${error instanceof Error ? error.message : error}`);
  }
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  try {
    const dir = process.env.SCG_INSTALL_DIR ?? "";
    if (dir === "") fail("SCG_INSTALL_DIR is not set");
    const { summary } = verifyScannerInstall({
      lockfile: readJson(join(dir, "package-lock.json"), "package-lock.json"),
      installedManifest: readJson(join(dir, "node_modules", PACKAGE, "package.json"), `the installed ${PACKAGE}/package.json`),
      audit: readJson(process.env.SCG_AUDIT_JSON ?? "", "the npm audit signatures report"),
      npmVersion: (process.env.SCG_NPM_VERSION ?? "").trim(),
      version: process.env.SCG_VERSION,
      repository: process.env.SCG_EXPECTED_REPOSITORY,
      repositoryId: process.env.SCG_EXPECTED_REPOSITORY_ID,
      workflow: process.env.SCG_EXPECTED_WORKFLOW,
    });
    console.log(`Scanner install verified: ${summary}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`::error title=supply-chain-guard install verification failed::${message}`);
    console.error(`supply-chain-guard install verification failed; the scanner will not run: ${message}`);
    process.exit(1);
  }
}
