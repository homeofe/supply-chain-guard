import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  evaluateVersionDrift,
  checkRegistryVersionDrift,
} from "../publishing-anomaly-detector.js";

/**
 * Registry version-drift check (v5.9, opt-in --check-registry).
 *
 * Compares the LOCAL source package.json version against the npm registry
 * 'latest' dist-tag. The concerning signal is "the code you are auditing is a
 * major version behind what npm actually installs" (e.g. TencentDB-Agent-Memory
 * source 0.3.6 vs npm latest 1.0.0). Network is fully injectable so these tests
 * never touch the wire.
 */
describe("evaluateVersionDrift (pure, no network)", () => {
  it("flags source a major version behind the npm latest (0.3.6 vs 1.0.0)", () => {
    const f = evaluateVersionDrift("@x/pkg", "0.3.6", "1.0.0");
    expect(f).not.toBeNull();
    expect(f?.rule).toBe("REGISTRY_VERSION_DRIFT_MAJOR");
    expect(f?.severity).toBe("medium");
  });

  it("does not flag when source and registry share a major (minor lag is benign)", () => {
    expect(evaluateVersionDrift("p", "1.2.0", "1.9.3")).toBeNull();
  });

  it("does not flag equal versions", () => {
    expect(evaluateVersionDrift("p", "1.0.0", "1.0.0")).toBeNull();
  });

  it("does not flag when source is ahead of registry (unreleased dev)", () => {
    expect(evaluateVersionDrift("p", "2.0.0", "1.5.0")).toBeNull();
  });

  it("returns null on unparseable versions", () => {
    expect(evaluateVersionDrift("p", "not-a-version", "1.0.0")).toBeNull();
    expect(evaluateVersionDrift("p", "1.0.0", "")).toBeNull();
  });
});

describe("checkRegistryVersionDrift (injected fetcher, no network)", () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join("/tmp", "scg-drift-")); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it("flags a real major drift using an injected registry fetcher", async () => {
    fs.writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({ name: "@tencentdb-agent-memory/memory-tencentdb", version: "0.3.6" }),
    );
    const findings = await checkRegistryVersionDrift(dir, async () => "1.0.0");
    expect(findings.some((f) => f.rule === "REGISTRY_VERSION_DRIFT_MAJOR")).toBe(true);
  });

  it("returns nothing (and does not throw) when the registry is unreachable/unpublished", async () => {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", version: "0.3.6" }));
    const findings = await checkRegistryVersionDrift(dir, async () => null);
    expect(findings).toHaveLength(0);
  });

  it("does not throw when the fetcher itself rejects (offline-safe)", async () => {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "p", version: "0.3.6" }));
    const findings = await checkRegistryVersionDrift(dir, async () => { throw new Error("ENOTFOUND"); });
    expect(findings).toHaveLength(0);
  });

  it("returns nothing when there is no package.json", async () => {
    const findings = await checkRegistryVersionDrift(dir, async () => "9.9.9");
    expect(findings).toHaveLength(0);
  });

  it("returns nothing when package.json lacks name or version", async () => {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ description: "no name/version" }));
    const findings = await checkRegistryVersionDrift(dir, async () => "1.0.0");
    expect(findings).toHaveLength(0);
  });
});
