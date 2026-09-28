/**
 * The Action verifies the scanner it installs before running it.
 *
 * It used to run `npm install -g supply-chain-guard@<version>`: pinned by
 * version, not by content, so a registry or CDN response carrying other bytes
 * under that version would have run as the scanner. The install step now
 * installs into a throwaway project, lets `npm audit signatures` verify the
 * registry signature and the Sigstore provenance cryptographically, and then
 * scripts/verify-action-install.mjs requires that the provenance EXISTS and was
 * signed by this repository's release workflow at the version's tag, for the
 * tarball on disk. npm alone accepts a package with no attestation, and a valid
 * attestation from any other repository.
 *
 * The fixture is real data: the fields the verifier reads, extracted from
 * `npm audit signatures --json --include-attestations` output for the published
 * 6.3.1 (npm 12.0.2, 2026-09-28), plus the signing certificate of an unrelated
 * package whose provenance was built in another repository. Certificates are
 * stored as hex and the DSSE statement decoded, and re-encoded here into the
 * bundle shape npm prints. Stored as npm printed them, the base64 blobs read as
 * encoded payloads to this scanner's own entropy rule, at high severity, in a
 * scan of this repository.
 */

import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import pkg from "../../package.json";
import {
  verifyScannerInstall,
  certificateIdentity,
  SLSA_PROVENANCE_V1,
} from "../../scripts/verify-action-install.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const fixtureDir = path.join(repoRoot, "src", "__tests__", "fixtures", "action-install");
const readFixture = (name: string) => JSON.parse(fs.readFileSync(path.join(fixtureDir, name), "utf8"));

const VERSION = "6.3.1";
const INTEGRITY = "sha512-J4Eg18mBSioFOMMfsTUqaro/wRlF082dr5SZADxcwN2rn/1JMRsYv7OeGebTleerY3eP850Aa+GBiVXYFD7tzA==";
const REPOSITORY = "homeofe/supply-chain-guard";
const REPOSITORY_ID = "1185867580";
const WORKFLOW = ".github/workflows/ci.yml";

type Audit = {
  invalid: unknown[];
  missing: unknown[];
  verified?: Array<{
    name: string;
    version: string;
    location: string;
    attestationBundles: Array<{ predicateType: string; bundle: Record<string, unknown> }>;
  }>;
};

const fixture = readFixture("npm-provenance-6.3.1.json");
const base64OfHex = (hex: string) => Buffer.from(hex, "hex").toString("base64");
const foreignCertificate = () => ({ certificate: { rawBytes: base64OfHex(fixture.foreignProvenance.certificateDerHex) } });

/** The audit report npm printed for the 6.3.1 install, rebuilt from the fixture. */
const realAudit = (): Audit => {
  const { scanner } = fixture;
  const provenance = scanner.provenance;
  return {
    invalid: [...fixture.audit.invalid],
    missing: [...fixture.audit.missing],
    verified: [
      {
        name: scanner.name,
        version: scanner.version,
        location: scanner.location,
        attestationBundles: (scanner.attestationPredicates as string[]).map((predicateType) => ({
          predicateType,
          bundle:
            predicateType === SLSA_PROVENANCE_V1
              ? {
                  mediaType: provenance.mediaType,
                  verificationMaterial: { certificate: { rawBytes: base64OfHex(provenance.certificateDerHex) } },
                  dsseEnvelope: {
                    payloadType: provenance.payloadType,
                    payload: Buffer.from(JSON.stringify(provenance.statement)).toString("base64"),
                    signatures: [],
                  },
                }
              : { note: "the npm publish attestation; the verifier does not read it" },
        })),
      },
    ],
  };
};
const lockfile = (overrides: Record<string, unknown> = {}) => ({
  name: "scg-action-install",
  lockfileVersion: 3,
  packages: {
    "": { dependencies: { "supply-chain-guard": VERSION } },
    "node_modules/supply-chain-guard": {
      version: VERSION,
      resolved: `https://registry.npmjs.org/supply-chain-guard/-/supply-chain-guard-${VERSION}.tgz`,
      integrity: INTEGRITY,
      ...overrides,
    },
  },
});

function inputs(overrides: Record<string, unknown> = {}) {
  return {
    lockfile: lockfile(),
    installedManifest: { name: "supply-chain-guard", version: VERSION },
    audit: realAudit(),
    npmVersion: "11.19.0",
    version: VERSION,
    repository: REPOSITORY,
    repositoryId: REPOSITORY_ID,
    workflow: WORKFLOW,
    ...overrides,
  };
}

function provenanceOf(audit: Audit) {
  const entry = audit.verified!.find((e) => e.name === "supply-chain-guard")!;
  return entry.attestationBundles.find((b) => b.predicateType === SLSA_PROVENANCE_V1)!;
}

describe("verifyScannerInstall: the published release passes", () => {
  it("accepts the real 6.3.1 install and names what it verified", () => {
    const { summary } = verifyScannerInstall(inputs());
    expect(summary).toContain(`https://github.com/${REPOSITORY}/${WORKFLOW}@refs/tags/v${VERSION}`);
    expect(summary).toContain(REPOSITORY_ID);
  });

  it("reads the signing identity from the Fulcio certificate, not from the statement", () => {
    const identity = certificateIdentity(provenanceOf(realAudit()).bundle);
    expect(identity).toEqual({
      san: `URI:https://github.com/${REPOSITORY}/${WORKFLOW}@refs/tags/v${VERSION}`,
      issuer: "https://token.actions.githubusercontent.com",
      sourceRepository: `https://github.com/${REPOSITORY}`,
      sourceRepositoryRef: `refs/tags/v${VERSION}`,
      sourceRepositoryId: REPOSITORY_ID,
    });
  });
});

describe("verifyScannerInstall: fails closed", () => {
  it.each([
    ["npm too old to report attestations", { npmVersion: "11.11.0" }, /npm 11\.11\.0 cannot report/],
    ["npm version unknown", { npmVersion: "" }, /cannot report the attestations/],
    ["spoofed expected repository", { repository: "attacker/supply-chain-guard" }, /not https:\/\/github\.com\/attacker/],
    ["expected repository id differs", { repositoryId: "1" }, /repository id 1185867580, not 1/],
    ["expected workflow differs", { workflow: ".github/workflows/release.yml" }, /signed by URI:.*ci\.yml.*not URI:.*release\.yml/],
    ["a different version expected", { version: "6.3.2" }, /resolved supply-chain-guard@6\.3\.1, not 6\.3\.2/],
    ["no expected repository configured", { repository: "" }, /no expected repository/],
  ])("%s", (_name, overrides, message) => {
    expect(() => verifyScannerInstall(inputs(overrides))).toThrow(message);
  });

  it("a tampered tarball: the installed integrity is not the attested subject", () => {
    const tampered = `sha512-${Buffer.alloc(64, 1).toString("base64")}`;
    expect(() => verifyScannerInstall(inputs({ lockfile: lockfile({ integrity: tampered }) }))).toThrow(
      /does not describe the installed tarball/,
    );
  });

  it("resolved from anywhere but the public registry", () => {
    expect(() =>
      verifyScannerInstall(inputs({ lockfile: lockfile({ resolved: "https://mirror.invalid/scg.tgz" }) })),
    ).toThrow(/resolved from https:\/\/mirror\.invalid/);
  });

  it("the installed package is not the one that was verified", () => {
    expect(() =>
      verifyScannerInstall(inputs({ installedManifest: { name: "supply-chain-guard", version: "6.3.0" } })),
    ).toThrow(/installed package is supply-chain-guard@6\.3\.0/);
  });

  it("a package without provenance: npm verified no attestation for it", () => {
    const audit = realAudit();
    audit.verified = [];
    expect(() => verifyScannerInstall(inputs({ audit }))).toThrow(/verified no attestation for supply-chain-guard@6\.3\.1/);
  });

  it("only the publish attestation, no SLSA provenance", () => {
    const audit = realAudit();
    const entry = audit.verified![0]!;
    entry.attestationBundles = entry.attestationBundles.filter((b) => b.predicateType !== SLSA_PROVENANCE_V1);
    expect(() => verifyScannerInstall(inputs({ audit }))).toThrow(/no SLSA provenance attestation/);
  });

  it("npm did not honour --include-attestations", () => {
    const audit = realAudit();
    delete audit.verified;
    expect(() => verifyScannerInstall(inputs({ audit }))).toThrow(/reported no attestation details/);
  });

  it.each([["invalid"], ["missing"]] as const)("npm reported a %s signature", (field) => {
    const audit = realAudit();
    audit[field] = [{ name: "commander", version: "14.0.3" }];
    expect(() => verifyScannerInstall(inputs({ audit }))).toThrow(/invalid or missing signatures: commander@14\.0\.3/);
  });

  it("a valid provenance certificate from another repository", () => {
    // The statement still names this package and digest (a signer writes what
    // it likes), but the certificate Fulcio issued belongs to another
    // repository's workflow. npm accepts that bundle; this check does not.
    const audit = realAudit();
    (provenanceOf(audit).bundle as { verificationMaterial: unknown }).verificationMaterial = foreignCertificate();
    expect(() => verifyScannerInstall(inputs({ audit }))).toThrow(
      /built in https:\/\/github\.com\/sigstore\/sigstore-js, not https:\/\/github\.com\/homeofe\/supply-chain-guard/,
    );
  });

  it("a statement that names another workflow than the certificate", () => {
    const audit = realAudit();
    const envelope = provenanceOf(audit).bundle.dsseEnvelope as { payload: string };
    const statement = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
    statement.predicate.buildDefinition.externalParameters.workflow.ref = "refs/heads/main";
    envelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    expect(() => verifyScannerInstall(inputs({ audit }))).toThrow(/statement names .*@refs\/heads\/main/);
  });

  it("a bundle with no certificate", () => {
    const audit = realAudit();
    (provenanceOf(audit).bundle as { verificationMaterial: unknown }).verificationMaterial = {};
    expect(() => verifyScannerInstall(inputs({ audit }))).toThrow(/carries no signing certificate/);
  });
});

// ---------------------------------------------------------------------------
// action.yml wiring
// ---------------------------------------------------------------------------

const action = fs.readFileSync(path.join(repoRoot, "action.yml"), "utf8");
const installStart = action.indexOf("    - name: Install supply-chain-guard");
const installEnd = action.indexOf("    - name: Run scan");
const installStep = action.slice(installStart, installEnd);

function literalBlock(section: string, marker: string, indent: number): string {
  const start = section.indexOf(marker);
  if (start < 0) throw new Error(`Missing block marker: ${marker}`);
  const lines = section.slice(start + marker.length).replace(/^\r?\n/, "").split(/\r?\n/);
  const prefix = " ".repeat(indent);
  const body: string[] = [];
  for (const line of lines) {
    if (line.length > 0 && !line.startsWith(prefix)) break;
    body.push(line.startsWith(prefix) ? line.slice(indent) : "");
  }
  return body.join("\n");
}

const installScript = literalBlock(installStep, "      run: |", 8);
const stepEnv = (name: string) => new RegExp(`\\n        ${name}: "([^"]*)"`).exec(installStep)?.[1];

describe("action.yml installs and verifies before it scans", () => {
  it("pins the package.json version and this repository's identity", () => {
    expect(installStart).toBeGreaterThan(-1);
    expect(installEnd).toBeGreaterThan(installStart);
    expect(stepEnv("SCG_VERSION")).toBe(pkg.version);
    expect(`https://github.com/${stepEnv("SCG_EXPECTED_REPOSITORY")}.git`).toBe(pkg.repository.url);
    expect(stepEnv("SCG_EXPECTED_REPOSITORY_ID")).toBe(REPOSITORY_ID);
    // The workflow the identity names is the one that publishes with provenance.
    const workflow = stepEnv("SCG_EXPECTED_WORKFLOW")!;
    expect(fs.readFileSync(path.join(repoRoot, workflow), "utf8")).toContain("npm publish --access public --provenance");
  });

  it("resolves the newest Node 24 so a stale tool cache cannot supply an npm below the floor", () => {
    const setupStart = action.indexOf("    - name: Setup Node.js");
    expect(setupStart).toBeGreaterThan(-1);
    expect(setupStart).toBeLessThan(installStart);
    const setupStep = action.slice(setupStart, installStart);
    expect(setupStep).toMatch(/\n {8}node-version: "24"\r?\n/);
    expect(setupStep).toMatch(/\n {8}check-latest: true\r?\n/);
  });

  it("installs into a throwaway project with scripts disabled, never globally", () => {
    expect(installScript).not.toMatch(/npm install[^\n]*(?:\s-g\b|--global)/);
    expect(installScript).toMatch(/npm install --prefix "\$SCG_INSTALL_DIR"[^\n]*--ignore-scripts/);
    expect(installScript).toContain("set -euo pipefail");
  });

  it("orders install, npm verification, provenance verification, then PATH", () => {
    const order = [
      "npm install --prefix",
      "npm audit signatures --json --include-attestations",
      'node "$GITHUB_ACTION_PATH/scripts/verify-action-install.mjs"',
      'echo "$SCG_INSTALL_DIR/node_modules/.bin" >> "$GITHUB_PATH"',
    ].map((marker) => installScript.indexOf(marker));
    expect(order.every((index) => index > -1)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });
});

describe("the install step as a shell script, against a stub npm", () => {
  const temps: string[] = [];
  afterEach(() => {
    for (const dir of temps.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  function runInstall(audit: unknown, options: { auditStatus?: number; npmVersion?: string } = {}) {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-action-install-"));
    temps.push(temp);
    const bin = path.join(temp, "bin");
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(temp, "lock.json"), JSON.stringify(lockfile()));
    fs.writeFileSync(path.join(temp, "audit.json"), JSON.stringify(audit));
    fs.writeFileSync(path.join(bin, "npm"), `#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case "$1" in
  --version) echo "$STUB_NPM_VERSION"; exit 0 ;;
  install)
    prefix=""
    while [ "$#" -gt 0 ]; do case "$1" in --prefix) prefix="$2"; shift 2 ;; *) shift ;; esac; done
    mkdir -p "$prefix/node_modules/supply-chain-guard" "$prefix/node_modules/.bin"
    cp "$STUB_LOCK" "$prefix/package-lock.json"
    printf '{"name":"supply-chain-guard","version":"${VERSION}"}' > "$prefix/node_modules/supply-chain-guard/package.json"
    exit 0 ;;
  audit) cat "$STUB_AUDIT"; exit "$STUB_AUDIT_STATUS" ;;
esac
exit 99
`);
    fs.chmodSync(path.join(bin, "npm"), 0o755);
    const scriptPath = path.join(temp, "install.sh");
    fs.writeFileSync(scriptPath, installScript);
    const githubPath = path.join(temp, "github-path.txt");
    fs.writeFileSync(githubPath, "");
    const result = spawnSync("bash", [scriptPath], {
      cwd: temp,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ""}`,
        RUNNER_TEMP: temp,
        GITHUB_PATH: githubPath,
        GITHUB_ACTION_PATH: repoRoot,
        // The fixture's release, not the pin: the fixture is 6.3.1 forever,
        // while the pin moves with every release. The identity values are the
        // step's own.
        SCG_VERSION: VERSION,
        SCG_EXPECTED_REPOSITORY: stepEnv("SCG_EXPECTED_REPOSITORY"),
        SCG_EXPECTED_REPOSITORY_ID: stepEnv("SCG_EXPECTED_REPOSITORY_ID"),
        SCG_EXPECTED_WORKFLOW: stepEnv("SCG_EXPECTED_WORKFLOW"),
        STUB_LOG: path.join(temp, "npm.log"),
        STUB_LOCK: path.join(temp, "lock.json"),
        STUB_AUDIT: path.join(temp, "audit.json"),
        STUB_AUDIT_STATUS: String(options.auditStatus ?? 0),
        STUB_NPM_VERSION: options.npmVersion ?? "11.19.0",
      },
    });
    return {
      status: result.status,
      stderr: result.stderr,
      githubPath: fs.readFileSync(githubPath, "utf8"),
      npmLog: fs.readFileSync(path.join(temp, "npm.log"), "utf8"),
    };
  }

  it("adds the verified install to PATH and nothing else", () => {
    const run = runInstall(realAudit());
    expect(run.status, run.stderr).toBe(0);
    expect(run.githubPath.trim()).toMatch(/scg-install\.[^/\\]+[/\\]node_modules[/\\]\.bin$/);
    expect(run.npmLog).toMatch(/^install --prefix \S+ --save-exact --ignore-scripts .*supply-chain-guard@6\.3\.1$/m);
    expect(run.npmLog).not.toMatch(/(?:^|\s)(?:-g|--global)(?:\s|$)/);
  });

  it("stops before PATH when the provenance belongs to another repository", () => {
    const audit = realAudit();
    (provenanceOf(audit).bundle as { verificationMaterial: unknown }).verificationMaterial = foreignCertificate();
    const run = runInstall(audit);
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain("::error title=supply-chain-guard install verification failed::");
    expect(run.githubPath).toBe("");
  });

  it("stops before PATH when the package carries no provenance", () => {
    const audit = realAudit();
    audit.verified = [];
    const run = runInstall(audit);
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain("verified no attestation");
    expect(run.githubPath).toBe("");
  });

  it("stops before PATH when npm audit signatures itself fails", () => {
    const audit = realAudit();
    audit.invalid = [{ name: "supply-chain-guard", version: VERSION }];
    const run = runInstall(audit, { auditStatus: 1 });
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain("npm audit signatures rejected the installed scanner");
    expect(run.githubPath).toBe("");
  });

  it("stops before PATH on an npm that cannot report attestations", () => {
    const run = runInstall(realAudit(), { npmVersion: "11.11.0" });
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain("npm 11.11.0 cannot report");
    expect(run.githubPath).toBe("");
  });
});
