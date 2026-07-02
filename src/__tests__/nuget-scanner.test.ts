import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  scanNuGetFiles,
  scanPackagesLockContent,
  scanCsprojContent,
  scanNuGetConfigContent,
  isNuGetFile,
  hasNuGetFiles,
} from "../nuget-scanner.js";
import { matchPackageIOC } from "../threat-intel.js";

// Real bundled IOC (vpmdhaj Sicoob/Cloud-Secret campaign, name@version entries)
const MALICIOUS_ID = "Sicoob.Sdk";
const MALICIOUS_VERSION = "2.0.0";

function lockContent(name: string, resolved: string): string {
  return JSON.stringify({
    version: 1,
    dependencies: {
      "net8.0": {
        [name]: { type: "Direct", requested: `[${resolved}, )`, resolved, contentHash: "abc=" },
        "Newtonsoft.Json": { type: "Direct", requested: "[13.0.3, )", resolved: "13.0.3", contentHash: "def=" },
      },
    },
  });
}

describe("NuGet Scanner", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-nuget-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should identify NuGet-related files (case-insensitively)", () => {
    expect(isNuGetFile("packages.lock.json")).toBe(true);
    expect(isNuGetFile("nuget.config")).toBe(true);
    expect(isNuGetFile("NuGet.Config")).toBe(true);
    expect(isNuGetFile("MyApp.csproj")).toBe(true);
    expect(isNuGetFile("package.json")).toBe(false);
    expect(isNuGetFile("packages.config.bak")).toBe(false);
  });

  describe("packages.lock.json scanning", () => {
    it("should flag a resolved package matching a bundled nuget: IOC", () => {
      const findings = scanPackagesLockContent(
        lockContent(MALICIOUS_ID, MALICIOUS_VERSION),
        "packages.lock.json",
      );
      const hit = findings.find((f) => f.rule === "NUGET_MALICIOUS_PACKAGE");
      expect(hit).toBeDefined();
      expect(hit?.severity).toBe("critical");
      expect(hit?.category).toBe("malware");
      expect(hit?.confidence).toBeGreaterThan(0);
    });

    it("should match NuGet package ids case-insensitively", () => {
      const findings = scanPackagesLockContent(
        lockContent("sicoob.sdk", MALICIOUS_VERSION),
        "packages.lock.json",
      );
      expect(findings.some((f) => f.rule === "NUGET_MALICIOUS_PACKAGE")).toBe(true);
    });

    it("should not flag a non-listed version of a versioned IOC", () => {
      const findings = scanPackagesLockContent(
        lockContent(MALICIOUS_ID, "9.9.9"),
        "packages.lock.json",
      );
      expect(findings).toHaveLength(0);
    });

    it("should not flag a clean packages.lock.json", () => {
      const findings = scanPackagesLockContent(
        lockContent("Serilog", "3.1.1"),
        "packages.lock.json",
      );
      expect(findings).toHaveLength(0);
    });

    it("should not crash on malformed packages.lock.json", () => {
      expect(() => scanPackagesLockContent("{ nope", "packages.lock.json")).not.toThrow();
      expect(scanPackagesLockContent("{ nope", "packages.lock.json")).toHaveLength(0);
      expect(scanPackagesLockContent('{"dependencies": 42}', "packages.lock.json")).toHaveLength(0);
      expect(
        scanPackagesLockContent('{"dependencies": {"net8.0": {"X": null}}}', "packages.lock.json"),
      ).toHaveLength(0);
    });
  });

  describe("csproj scanning", () => {
    it("should flag a PackageReference matching an IOC", () => {
      const content = [
        "<Project Sdk=\"Microsoft.NET.Sdk\">",
        "  <ItemGroup>",
        `    <PackageReference Include="${MALICIOUS_ID}" Version="${MALICIOUS_VERSION}" />`,
        "  </ItemGroup>",
        "</Project>",
      ].join("\n");
      const findings = scanCsprojContent(content, "App.csproj");
      const hit = findings.find((f) => f.rule === "NUGET_MALICIOUS_PACKAGE");
      expect(hit).toBeDefined();
      expect(hit?.line).toBe(3);
    });

    it("should handle attribute order and case variations", () => {
      const content = `<packagereference version="${MALICIOUS_VERSION}" include="sicoob.sdk" />`;
      const findings = scanCsprojContent(content, "App.csproj");
      expect(findings.some((f) => f.rule === "NUGET_MALICIOUS_PACKAGE")).toBe(true);
    });

    it("should not flag clean PackageReferences", () => {
      const content = [
        "<Project Sdk=\"Microsoft.NET.Sdk\">",
        "  <ItemGroup>",
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />',
        '    <PackageReference Include="Serilog" Version="3.1.1" />',
        "  </ItemGroup>",
        "</Project>",
      ].join("\n");
      const findings = scanCsprojContent(content, "App.csproj");
      expect(findings).toHaveLength(0);
    });

    it("should flag plain-http RestoreSources feeds", () => {
      const content = [
        "<PropertyGroup>",
        "  <RestoreSources>https://api.nuget.org/v3/index.json;http://feed.internal.example/v3/index.json</RestoreSources>",
        "</PropertyGroup>",
      ].join("\n");
      const findings = scanCsprojContent(content, "App.csproj");
      const hits = findings.filter((f) => f.rule === "NUGET_HTTP_FEED");
      expect(hits).toHaveLength(1);
      expect(hits[0]?.severity).toBe("medium");
      expect(hits[0]?.category).toBe("supply-chain");
    });
  });

  describe("nuget.config scanning", () => {
    it("should flag plain-http package sources", () => {
      const content = [
        "<configuration>",
        "  <packageSources>",
        '    <add key="internal" value="http://feed.internal.example/v3/index.json" />',
        '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />',
        "  </packageSources>",
        "</configuration>",
      ].join("\n");
      const findings = scanNuGetConfigContent(content, "nuget.config");
      const hits = findings.filter((f) => f.rule === "NUGET_HTTP_FEED");
      expect(hits).toHaveLength(1);
      expect(hits[0]?.line).toBe(3);
    });

    it("should not flag https-only nuget.config", () => {
      const content = [
        "<configuration>",
        "  <packageSources>",
        '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />',
        "  </packageSources>",
        "</configuration>",
      ].join("\n");
      expect(scanNuGetConfigContent(content, "nuget.config")).toHaveLength(0);
    });
  });

  describe("directory scanning", () => {
    it("should detect NuGet files in a directory", () => {
      expect(hasNuGetFiles(tmpDir)).toBe(false);
      fs.writeFileSync(path.join(tmpDir, "App.csproj"), "<Project />");
      expect(hasNuGetFiles(tmpDir)).toBe(true);
    });

    it("should scan lockfile, csproj, and nuget.config from a directory", () => {
      fs.writeFileSync(
        path.join(tmpDir, "packages.lock.json"),
        lockContent(MALICIOUS_ID, MALICIOUS_VERSION),
      );
      fs.writeFileSync(
        path.join(tmpDir, "App.csproj"),
        `<Project><ItemGroup><PackageReference Include="${MALICIOUS_ID}" Version="${MALICIOUS_VERSION}" /></ItemGroup></Project>`,
      );
      fs.writeFileSync(
        path.join(tmpDir, "nuget.config"),
        '<configuration><packageSources><add key="i" value="http://feed.internal.example/" /></packageSources></configuration>',
      );
      const findings = scanNuGetFiles(tmpDir);
      expect(findings.filter((f) => f.rule === "NUGET_MALICIOUS_PACKAGE")).toHaveLength(2);
      expect(findings.some((f) => f.rule === "NUGET_HTTP_FEED")).toBe(true);
    });

    it("should return no findings for an empty directory", () => {
      expect(scanNuGetFiles(tmpDir)).toHaveLength(0);
    });
  });

  describe("matchPackageIOC (nuget)", () => {
    it("should match name@version IOCs only on listed versions", () => {
      expect(matchPackageIOC("nuget", MALICIOUS_ID, MALICIOUS_VERSION)).not.toBeNull();
      expect(matchPackageIOC("nuget", MALICIOUS_ID, "2.0.4")).not.toBeNull();
      expect(matchPackageIOC("nuget", MALICIOUS_ID, "9.9.9")).toBeNull();
      // no version supplied: versioned IOCs must not fire
      expect(matchPackageIOC("nuget", MALICIOUS_ID)).toBeNull();
    });

    it("should compare NuGet ids case-insensitively", () => {
      expect(matchPackageIOC("nuget", "SICOOB.SDK", MALICIOUS_VERSION)).not.toBeNull();
    });
  });
});
