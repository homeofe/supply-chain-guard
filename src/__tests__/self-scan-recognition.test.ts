import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../scanner.js";
import type { ScanReport } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../..");
const TSC = path.join(ROOT, "node_modules", "typescript", "bin", "tsc");

/**
 * Regression for the "globally-installed binary flags supply-chain-guard's own
 * repo" false positive: a checkout of the tool's own source tree (full of
 * malicious IOC strings by design) must be recognized as own-source by its
 * package.json identity, independent of where the running binary is installed -
 * not only when the scanned path equals the installed package root.
 *
 * Uses a real bundled feed IOC to exercise the suppression, so this file is
 * itself listed in SELF_SCAN_INERT_FILES.
 */
const FEED_DOMAIN = "rti.cargomanbd.com"; // bundled Vidar C2 domain

function writeCheckout(dir: string, pkg: Record<string, unknown>): void {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(pkg));
  fs.mkdirSync(path.join(dir, "src"), { recursive: true });
  // A file at one of the tool's own source paths carrying an IOC string, exactly
  // as src/threat-intel.ts / src/ioc-blocklist.ts do.
  fs.writeFileSync(path.join(dir, "src", "threat-intel.ts"), `const c2 = "${FEED_DOMAIN}";\n`);
}

const iocFired = (findings: { rule: string }[]): boolean =>
  findings.some((f) => f.rule === "THREAT_INTEL_MATCH" || f.rule === "IOC_KNOWN_C2_DOMAIN");

const OWN_PACKAGE = {
  name: "supply-chain-guard",
  version: "1.0.0",
  repository: {
    type: "git",
    url: "git+https://github.com/homeofe/supply-chain-guard.git",
  },
};

describe("self-scan recognition (own source checkout)", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-selfscan-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("suppresses own IOC files when the checkout IS supply-chain-guard, regardless of install path", async () => {
    writeCheckout(dir, OWN_PACKAGE);
    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(iocFired(report.findings)).toBe(false);
  });

  it("still flags a third-party project that merely embeds the same IOC", async () => {
    writeCheckout(dir, { name: "some-other-app", version: "1.0.0" });
    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(iocFired(report.findings)).toBe(true);
  });

  it("does not let a hostile project spoof the suppression by forging only the name", async () => {
    // name matches but the repository does not point at homeofe/supply-chain-guard
    writeCheckout(dir, {
      name: "supply-chain-guard",
      version: "1.0.0",
      repository: { url: "https://github.com/attacker/evil" },
    });
    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(iocFired(report.findings)).toBe(true);
  });
  it.each([
    "https://github.com/homeofe/supply-chain-guard",
    "https://github.com/homeofe/supply-chain-guard.git",
    "git+https://github.com/homeofe/supply-chain-guard.git",
    "git://github.com/homeofe/supply-chain-guard.git",
    "ssh://git@github.com/homeofe/supply-chain-guard.git",
    "git+ssh://git@github.com/homeofe/supply-chain-guard.git",
    "git@github.com:homeofe/supply-chain-guard.git",
  ])("accepts the exact canonical repository identity: %s", async (repository) => {
    writeCheckout(dir, { ...OWN_PACKAGE, repository });
    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(iocFired(report.findings)).toBe(false);
  });

  it.each([
    "https://attacker.invalid/homeofe/supply-chain-guard",
    "https://github.com/attacker/supply-chain-guard",
    "https://github.com/homeofe/supply-chain-guard-mirror",
    "https://github.com/homeofe/supply-chain-guard?mirror=1",
    "https://github.com/homeofe/supply-chain-guard#mirror",
    "https://github.com/homeofe/supply-chain-guard/extra",
  ])("rejects repository identity lookalikes: %s", async (repository) => {
    writeCheckout(dir, { ...OWN_PACKAGE, repository });
    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(iocFired(report.findings)).toBe(true);
  });

  it.each([
    "src/broad-gap-pattern-matchers.ts",
    "dist/broad-gap-pattern-matchers.js",
  ])("suppresses only reviewed own-definition rules at %s", async (relativePath) => {
    writeCheckout(dir, OWN_PACKAGE);
    const target = path.join(dir, ...relativePath.split("/"));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(
      target,
      "gl_cv_host_cpu_c_abi = configure.ac; const lzcdrtfxyqiplpd = true;\n",
    );

    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(
      report.findings.some(
        (finding) => finding.file === relativePath && finding.rule === "XZ_BUILD_INJECT",
      ),
    ).toBe(false);
    expect(
      report.findings.some(
        (finding) => finding.file === relativePath && finding.rule === "GLASSWORM_MARKER",
      ),
    ).toBe(true);
  });

  it("does not exempt a declaration file from unrelated pattern scanning", async () => {
    writeCheckout(dir, OWN_PACKAGE);
    const relativePath = "dist/broad-gap-pattern-matchers.d.ts";
    const target = path.join(dir, ...relativePath.split("/"));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "declare const xz: 'gl_cv_host_cpu_c_abi = configure.ac';\n");

    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(
      report.findings.some(
        (finding) => finding.file === relativePath && finding.rule === "XZ_BUILD_INJECT",
      ),
    ).toBe(true);
  });
  it("does not give a third-party same-basename file the own-definition exemption", async () => {
    writeCheckout(dir, { name: "ordinary-package", version: "1.0.0" });
    const relativePath = "src/broad-gap-pattern-matchers.ts";
    fs.writeFileSync(
      path.join(dir, ...relativePath.split("/")),
      "gl_cv_host_cpu_c_abi = configure.ac;\n",
    );

    const report = await scan({ target: dir, format: "text", noHistory: true });
    expect(
      report.findings.some(
        (finding) => finding.file === relativePath && finding.rule === "XZ_BUILD_INJECT",
      ),
    ).toBe(true);
  });
});

describe("built repository self-scan", () => {
  let workdir: string;
  let checkout: string;
  let cleanReport: ScanReport;
  let payloadReport: ScanReport;

  beforeAll(async () => {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-built-selfscan-"));
    checkout = path.join(workdir, "checkout");

    const excludedRootEntries = new Set([
      ".claude",
      ".git",
      ".scg-cache",
      ".scg-history",
      ".vitest",
      "coverage",
      "dist",
      "node_modules",
    ]);
    fs.cpSync(ROOT, checkout, {
      recursive: true,
      filter: (source) => {
        const relativePath = path.relative(ROOT, source).replace(/\\/g, "/");
        const rootEntry = relativePath.split("/")[0] ?? "";
        return relativePath === "" || !excludedRootEntries.has(rootEntry);
      },
    });

    // Build current production sources into the isolated checkout. This avoids
    // racing other Vitest workers over the repository's real dist directory.
    execFileSync(
      process.execPath,
      [TSC, "-p", path.join(ROOT, "tsconfig.json"), "--outDir", path.join(checkout, "dist")],
      { cwd: ROOT, stdio: "pipe" },
    );

    cleanReport = await scan({ target: checkout, format: "json", noHistory: true });

    // dist remains globally scannable: an arbitrary built payload does not
    // inherit suppression merely because this is supply-chain-guard.
    fs.writeFileSync(
      path.join(checkout, "dist", "payload.js"),
      `const c2 = "${FEED_DOMAIN}";\n`,
    );

    // The exact inert path suppresses IOC-table matches only. Independent
    // executable malware behavior at that path must still fire.
    fs.appendFileSync(
      path.join(checkout, "dist", "threat-intel.js"),
      '\neval(atob("ZXZhbA=="));\n',
    );
    payloadReport = await scan({ target: checkout, format: "json", noHistory: true });
  }, 60_000);

  afterAll(() => {
    fs.rmSync(workdir, { recursive: true, force: true });
  });

  it("builds the repository and retains a low aggregate self-scan verdict", () => {
    const severe = cleanReport.findings.filter(
      (finding) => finding.severity === "critical" || finding.severity === "high",
    );
    expect(
      severe.map((finding) => `${finding.severity}:${finding.rule}:${finding.file ?? "."}`),
    ).toEqual([]);
    // Severe-list emptiness alone is insufficient: enough independent medium
    // findings can still inflate the aggregate verdict to high or critical.
    expect(cleanReport.score).toBeLessThanOrEqual(10);
    expect(["clean", "low"]).toContain(cleanReport.riskLevel);
  });

  it("still scans an arbitrary payload under dist", () => {
    expect(
      payloadReport.findings.some(
        (finding) =>
          finding.file === "dist/payload.js" &&
          (finding.rule === "THREAT_INTEL_MATCH" ||
            finding.rule === "IOC_KNOWN_C2_DOMAIN"),
      ),
    ).toBe(true);
  });

  it("still scans executable behavior in an inert compiled counterpart", () => {
    expect(
      payloadReport.findings.some(
        (finding) =>
          finding.file === "dist/threat-intel.js" &&
          finding.rule === "EVAL_ATOB",
      ),
    ).toBe(true);
  });
});
