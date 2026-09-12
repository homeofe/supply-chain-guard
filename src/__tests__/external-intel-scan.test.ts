import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";

const tempDirs: string[] = [];

function fixture(
  packageLock = false,
  packageName = "fixture-app",
  dependencyName = "fixture-dependency",
): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-external-scan-"));
  tempDirs.push(dir);
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({
      name: packageName,
      version: "1.0.0",
      dependencies: packageLock ? { [dependencyName]: "2.0.0" } : {},
    }),
  );
  if (packageLock) {
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: packageName,
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": { name: packageName, version: "1.0.0" },
          [`node_modules/${dependencyName}`]: { name: dependencyName, version: "2.0.0" },
        },
      }),
    );
  }
  return dir;
}

afterEach(() => {
  vi.unstubAllGlobals();
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("external intelligence scan integration", () => {
  it("queries resolved lockfile dependencies and rejects a confirmed OSV malicious package", async () => {
    const queried: string[] = [];
    const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const packageName = `fixture-app-${suffix}`;
    const dependencyName = `fixture-dependency-${suffix}`;
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("api.osv.dev")) {
        const body = JSON.parse(String(init?.body)) as { package: { name: string } };
        queried.push(body.package.name);
        return {
          ok: true,
          json: async () => ({
            vulns: body.package.name === dependencyName
              ? [{ id: "MAL-2026-0001", summary: "Confirmed malicious package" }]
              : [],
          }),
        } as Response;
      }
      throw new Error(`unexpected request: ${url}`);
    }));

    const report = await scan({
      target: fixture(true, packageName, dependencyName),
      externalIntel: true,
      noHistory: true,
    });

    expect(queried.sort()).toEqual([dependencyName, packageName].sort());
    expect(report.externalIntel?.packagesQueried).toBe(2);
    expect(report.twoTierVerdict?.tier1Blocked).toBe(true);
    expect(report.twoTierVerdict?.verdict).toBe("CRITICAL / REJECT");
    expect(report.twoTierVerdict?.exitCode).toBe(2);
    expect(report.sbomDocument?.vulnerabilities?.find((v) => v.id === "MAL-2026-0001")?.analysis.state)
      .toBe("exploitable");
  });

  it("marks feed outages as partial coverage and never reports a passing verdict", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("offline");
    }));

    const report = await scan({ target: fixture(false, "outage-fixture-app"), externalIntel: true, noHistory: true });

    expect(report.externalIntel?.statuses.osv).toBe("unavailable");
    expect(report.externalIntel?.partial).toBe(true);
    expect(report.externalIntel?.notes.join(" ")).toContain("coverage incomplete");
    expect(report.twoTierVerdict?.exitCode).toBeGreaterThanOrEqual(1);
    expect(report.twoTierVerdict?.verdict).not.toBe("LOW / PASS");
  });

  it("keeps the default scanner offline", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("network should not be reached");
    });
    vi.stubGlobal("fetch", fetchMock);

    await scan({ target: fixture(), noHistory: true });

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
