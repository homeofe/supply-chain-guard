import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";

describe("issue #24 IOC filename-evasion regression", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-ioc-evasion-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("scans IOC payloads in scanner-like and test-like target paths", async () => {
    const testsDir = path.join(tempDir, "tests");
    fs.mkdirSync(testsDir, { recursive: true });

    const knownC2 = "147.45.197.92";
    fs.writeFileSync(
      path.join(tempDir, "reporter.js"),
      `export const endpoint = "${knownC2}";\n`,
    );
    fs.writeFileSync(
      path.join(testsDir, "payload.test.js"),
      `export const endpoint = "${knownC2}";\n`,
    );

    const report = await scan({
      target: tempDir,
      format: "json",
      noHistory: true,
    });

    const detectedFiles = report.findings
      .filter((finding) => finding.rule === "IOC_KNOWN_C2_IP")
      .map((finding) => finding.file);

    expect(detectedFiles).toEqual(
      expect.arrayContaining(["reporter.js", "tests/payload.test.js"]),
    );
  });
});
