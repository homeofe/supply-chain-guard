import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("score consistency", () => {
  it("keeps informational npm transitive inventory visible without adding risk or reducing trust", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-score-info-"));
    tempDirs.push(dir);
    fs.writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { direct: "1.0.0" } }),
    );
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "fixture",
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": { name: "fixture", version: "1.0.0", dependencies: { direct: "1.0.0" } },
          "node_modules/direct": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/direct/-/direct-1.0.0.tgz",
            integrity: `sha512-${"A".repeat(80)}`,
          },
          "node_modules/transitive": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/transitive/-/transitive-1.0.0.tgz",
            integrity: `sha512-${"B".repeat(80)}`,
          },
        },
      }),
    );

    const report = await scan({ target: dir, format: "json", noHistory: true });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule: "LOCKFILE_ORPHANED_DEPENDENCY",
          severity: "info",
        }),
      ]),
    );
    expect(report.score).toBe(0);
    expect(report.riskLevel).toBe("clean");
    expect(report.trustBreakdown?.dependencyTrust.score).toBe(100);
  });
});
