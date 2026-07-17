import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";

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

describe("self-scan recognition (own source checkout)", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-selfscan-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("suppresses own IOC files when the checkout IS supply-chain-guard, regardless of install path", async () => {
    writeCheckout(dir, {
      name: "supply-chain-guard",
      version: "1.0.0",
      repository: { type: "git", url: "git+https://github.com/homeofe/supply-chain-guard.git" },
    });
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
});
