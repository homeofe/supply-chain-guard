import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { checkPackageName, checkDependencies } from "../npm-scanner.js";
import { getBundledFeedRef } from "../threat-intel.js";
import type { Finding } from "../types.js";

describe("T-020: npm scanner threat feed source", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-t020-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("detects refreshed feed entries by default (Option B coverage parity)", () => {
    const fakeThreatName = "malicious-zero-day-pkg-t020";
    const refreshedFeed = [
      ...getBundledFeedRef(),
      {
        type: "package" as const,
        value: fakeThreatName,
        source: "https://github.com/advisories/GHSA-fake-t020",
        confidence: 0.99,
      },
    ];

    // Default checkPackageName with refreshed feed:
    const findings: Finding[] = [];
    checkPackageName(fakeThreatName, findings, refreshedFeed);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("MALICIOUS_PACKAGE_NAME");
    expect(findings[0].severity).toBe("critical");

    // With bundled feed (hermetic mode):
    const hermeticFindings: Finding[] = [];
    checkPackageName(fakeThreatName, hermeticFindings, getBundledFeedRef());
    expect(hermeticFindings).toHaveLength(0);
  });

  it("detects refreshed malicious dependencies by default", () => {
    const fakeThreatDep = "malicious-zero-day-dep-t020";
    const refreshedFeed = [
      ...getBundledFeedRef(),
      {
        type: "package" as const,
        value: fakeThreatDep,
        source: "https://github.com/advisories/GHSA-fake-t020-dep",
        confidence: 0.99,
      },
    ];

    const findings: Finding[] = [];
    checkDependencies(
      { dependencies: { [fakeThreatDep]: "^1.0.0" } },
      findings,
      refreshedFeed,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("MALICIOUS_DEPENDENCY");
    expect(findings[0].severity).toBe("critical");

    const hermeticFindings: Finding[] = [];
    checkDependencies(
      { dependencies: { [fakeThreatDep]: "^1.0.0" } },
      hermeticFindings,
      getBundledFeedRef(),
    );
    expect(hermeticFindings).toHaveLength(0);
  });
});
