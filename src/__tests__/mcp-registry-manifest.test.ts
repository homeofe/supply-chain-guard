import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// server.json was kept version-synced for months and never reached the MCP
// registry, because it could not: its description was 288 characters and the
// registry schema allows 100. The live registry answered
// 422 "expected length <= 100" on 2026-09-25. Nothing in the build knew the
// limit existed, so these assertions are that knowledge.

const root = path.resolve(__dirname, "..", "..");
const read = (f: string) => fs.readFileSync(path.join(root, f), "utf8");
const server = JSON.parse(read("server.json"));
const pkg = JSON.parse(read("package.json"));

describe("server.json satisfies the MCP registry schema", () => {
  it("keeps the description within the registry's 100-character limit", () => {
    expect(typeof server.description).toBe("string");
    expect(server.description.length).toBeGreaterThan(0);
    expect(server.description.length).toBeLessThanOrEqual(100);
  });

  it("names the server exactly as package.json's mcpName, which the registry verifies on npm", () => {
    expect(server.name).toMatch(/^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/);
    expect(pkg.mcpName).toBe(server.name);
  });

  it("points at this npm package over stdio", () => {
    expect(server.packages).toHaveLength(1);
    expect(server.packages[0]).toMatchObject({
      registryType: "npm",
      identifier: pkg.name,
      transport: { type: "stdio" },
    });
  });
});

// Text helpers in the style of release-ancestry.test.ts. Comment lines are
// dropped before any assertion: the comment above the job names the very
// strings asserted on ("releases/latest", "publish"), so a raw-text search would
// pass or fail on prose rather than on the steps that run.
const lines = (yaml: string) => yaml.split(/\r?\n/);
const executable = (yaml: string): string =>
  lines(yaml)
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");

function jobBlock(yaml: string, key: string): string {
  const all = lines(yaml);
  const start = all.findIndex((l) => new RegExp(`^ {2}${key}:\\s*$`).test(l));
  expect(start, `no job "${key}"`).toBeGreaterThan(-1);
  const end = all.findIndex((l, i) => i > start && /^ {2}[a-z][a-z0-9_-]*:\s*$/.test(l));
  return all.slice(start, end === -1 ? undefined : end).join("\n");
}

describe("the release job that publishes to the MCP registry", () => {
  const ci = read(".github/workflows/ci.yml");
  const job = executable(jobBlock(ci, "mcp-registry"));

  it("runs only after npm has the release, and only on a full-semver tag", () => {
    expect(job).toMatch(/^ {4}needs: publish\s*$/m);
    expect(job).toMatch(/^ {4}if: .*startsWith\(github\.ref, 'refs\/tags\/v'\).*contains\(github\.ref, '\.'\)/m);
  });

  it("holds only the permissions the OIDC login needs", () => {
    const perms = job.match(/^ {4}permissions:\n((?: {6}\S.*\n?)+)/m);
    expect(perms, "no job-level permissions block").not.toBeNull();
    const granted = perms![1]
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .sort();
    expect(granted).toEqual(["contents: read", "id-token: write"]);
  });

  it("verifies a pinned mcp-publisher before extracting it, and never fetches 'latest'", () => {
    expect(job).toMatch(/MCP_PUBLISHER_VERSION: "\d+\.\d+\.\d+"/);
    expect(job).toMatch(/MCP_PUBLISHER_SHA256: "[0-9a-f]{64}"/);
    const check = job.indexOf("sha256sum --check");
    const extract = job.indexOf("tar -xzf");
    expect(check).toBeGreaterThan(-1);
    expect(extract).toBeGreaterThan(check);
    expect(job).not.toMatch(/releases\/latest/);
    expect(job).not.toMatch(/\|\s*tar\b/);
  });

  it("validates before it publishes, with an OIDC login and no stored token", () => {
    const validate = job.indexOf('mcp-publisher" validate');
    const publish = job.indexOf('mcp-publisher" publish');
    expect(validate).toBeGreaterThan(-1);
    expect(publish).toBeGreaterThan(validate);
    expect(job).toContain("login github-oidc");
    expect(job).not.toMatch(/secrets\./);
  });

  it("does not hold back the GitHub Release", () => {
    const release = executable(jobBlock(ci, "release"));
    expect(release).toMatch(/^ {4}needs: publish\s*$/m);
    expect(release).not.toContain("mcp-registry");
  });
});
