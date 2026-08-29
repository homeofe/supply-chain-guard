/**
 * The remote package scanners must not report a clean verdict for a package they
 * did not read.
 *
 * Measured on v6.0.5 before this change: `supply-chain-guard npm <pkg>` whose
 * payload is a .ps1 printed "Type directory - 0 / 1 files scanned", RISK 2/100
 * LOW, produced zero findings and exited 0. The directory path has emitted a
 * coverage finding for exactly that state since issue 205; the npm, PyPI and
 * VS Code paths emitted neither, so the marquee check-before-you-install command
 * returned a clean verdict for a package whose contents it never opened.
 *
 * The severity and the PARTIAL_SCAN_RULES membership deliberately MATCH the
 * directory contract rather than exceeding it. src/scanner.ts records a measured
 * decision that "this tool does not read that language" must stay informational,
 * because failing the build on it turned exit 0 into exit 1 for every ordinary
 * Java, C#, Ruby, PHP or Kotlin project. This suite pins that choice too, so a
 * later well-meaning severity bump has to argue with the measurement.
 */
import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { makePackageCoverageFindings } from "../patterns.js";
import { PARTIAL_SCAN_RULES } from "../pattern-scanner.js";

const REPO = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

describe("package coverage contract", () => {
  it("says nothing when the package was actually read", () => {
    expect(makePackageCoverageFindings(12, 12)).toEqual([]);
    expect(makePackageCoverageFindings(12, 1)).toEqual([]);
  });

  it("reports zero coverage for an empty artifact", () => {
    const f = makePackageCoverageFindings(0, 0);
    expect(f).toHaveLength(1);
    expect(f[0]!.rule).toBe("SCAN_ZERO_COVERAGE");
    expect(f[0]!.description).toMatch(/cannot be a clean verdict/i);
  });

  it("reports unread contents when every file was outside the scannable set", () => {
    const f = makePackageCoverageFindings(7, 0);
    expect(f).toHaveLength(1);
    expect(f[0]!.rule).toBe("SCAN_NO_SCANNABLE_FILES");
    // The count must appear: "0 of 7" is the whole point of the finding.
    expect(f[0]!.description).toContain("0 of 7");
    expect(f[0]!.description).toMatch(/not a clean verdict/i);
  });

  it("stays informational, matching the directory contract", () => {
    // Not a severity oversight. See the file header: escalating this was measured
    // to break ordinary non-JS projects, and the directory path already decided it.
    for (const total of [0, 7]) {
      const f = makePackageCoverageFindings(total, 0);
      expect(f[0]!.severity).toBe("info");
    }
    expect(PARTIAL_SCAN_RULES.has("SCAN_NO_SCANNABLE_FILES")).toBe(false);
  });

  it("is actually wired into the npm scanner", () => {
    // A pure helper nobody calls is the defect this suite exists to prevent, and
    // the repo has shipped exactly that before (four engines exported, never
    // invoked). Assert the call site, not just the function.
    const src = fs.readFileSync(path.join(REPO, "src/npm-scanner.ts"), "utf-8");
    expect(src).toContain("makePackageCoverageFindings(");
    expect(src).toMatch(/findings\.push\(\s*\.\.\.makePackageCoverageFindings\(/);
  });
});

describe("scannable extensions cover the install-script vectors", () => {
  // Measured before this change: a byte-identical payload scoring critical in a
  // .js file produced ZERO findings in every extension below.
  it("reads the Windows install-script types", async () => {
    const { SCANNABLE_EXTENSIONS } = await import("../patterns.js");
    for (const ext of [".ps1", ".psm1", ".psd1", ".bat", ".cmd"]) {
      expect(SCANNABLE_EXTENSIONS.has(ext), `${ext} must be scanned`).toBe(true);
    }
  });

  it("reads the TypeScript module variants alongside .mjs and .cjs", async () => {
    const { SCANNABLE_EXTENSIONS } = await import("../patterns.js");
    for (const ext of [".mjs", ".cjs", ".mts", ".cts"]) {
      expect(SCANNABLE_EXTENSIONS.has(ext), `${ext} must be scanned`).toBe(true);
    }
  });

  it("reads the source languages of the ecosystems this scanner claims to support", async () => {
    const { SCANNABLE_EXTENSIONS } = await import("../patterns.js");
    // RubyGems, Composer and NuGet all have dedicated scanners and feed IOCs,
    // while their source files were never opened.
    for (const ext of [".rb", ".php", ".cs"]) {
      expect(SCANNABLE_EXTENSIONS.has(ext), `${ext} must be scanned`).toBe(true);
    }
  });

  it("still does not read binary or lockfile-shaped content", async () => {
    const { SCANNABLE_EXTENSIONS } = await import("../patterns.js");
    // The widening is deliberate and bounded: it adds executable text, not everything.
    for (const ext of [".png", ".jpg", ".lock", ".exe", ".dll", ".zip"]) {
      expect(SCANNABLE_EXTENSIONS.has(ext), `${ext} must NOT be scanned`).toBe(false);
    }
  });
});
