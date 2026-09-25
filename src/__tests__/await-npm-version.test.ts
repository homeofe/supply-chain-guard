import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

import { awaitNpmVersion } from "../../scripts/await-npm-version.mjs";

// The mcp-registry job publishes seconds after npm publish, and the MCP
// Registry verifies ownership by reading mcpName from the published
// package.json of that version. scripts/await-npm-version.mjs waits until npm
// serves it. "Not yet" is retried a bounded number of times; a document served
// with the wrong mcpName fails at once.

const ROOT = path.resolve(__dirname, "..", "..");
const VERSION = "9.9.9";
const MCP_NAME = "io.github.homeofe/supply-chain-guard";
const URL_ = `https://registry.npmjs.org/supply-chain-guard/${VERSION}`;

type Answer = "404" | "throw" | { version?: string; mcpName?: string };

function registry(answers: Answer[], then: Answer = { version: VERSION, mcpName: MCP_NAME }) {
  const calls: string[] = [];
  const fetchImpl = async (url: string) => {
    calls.push(url);
    const a = answers.shift() ?? then;
    if (a === "throw") throw new TypeError("fetch failed");
    if (a === "404") return new Response("not found", { status: 404 });
    return Response.json(a);
  };
  return { fetchImpl, calls };
}

const wait = (answers: Answer[], then?: Answer) => {
  const r = registry(answers, then);
  return {
    promise: awaitNpmVersion(VERSION, { mcpName: MCP_NAME, fetchImpl: r.fetchImpl, retryDelayMs: 0, attempts: 5 }),
    calls: r.calls,
  };
};

describe("awaitNpmVersion", () => {
  it("returns on the first answer when npm already serves the version", async () => {
    const r = wait([]);
    await expect(r.promise).resolves.toEqual({ attempts: 1 });
    expect(r.calls).toEqual([URL_]);
  });

  it("waits through 404s and requests that throw", async () => {
    await expect(wait(["404", "throw", "404"]).promise).resolves.toEqual({ attempts: 4 });
  });

  it("gives up after a bounded number of attempts and names the last answer", async () => {
    const r = wait([], "404");
    await expect(r.promise).rejects.toThrow(/after 5 attempts \(last status 404\)/);
    expect(r.calls).toHaveLength(5);
  });

  it("fails at once on a version served with another mcpName", async () => {
    // The control for the retry above: a wrong answer is not a delay.
    const r = wait([{ version: VERSION, mcpName: "io.github.someone/else" }]);
    await expect(r.promise).rejects.toThrow(/mcpName io\.github\.someone\/else/);
    expect(r.calls).toHaveLength(1);
  });

  it("fails at once on a served document without an mcpName", async () => {
    const r = wait([{ version: VERSION }]);
    await expect(r.promise).rejects.toThrow(/mcpName undefined/);
    expect(r.calls).toHaveLength(1);
  });

  it("refuses a version that is not an exact release, and a missing mcpName", async () => {
    const { fetchImpl } = registry([]);
    await expect(awaitNpmVersion("latest", { mcpName: MCP_NAME, fetchImpl })).rejects.toThrow(/release version/);
    await expect(awaitNpmVersion(VERSION, { mcpName: "", fetchImpl })).rejects.toThrow(/no mcpName/);
  });
});

describe("the mcp-registry job", () => {
  const ci = fs.readFileSync(path.join(ROOT, ".github", "workflows", "ci.yml"), "utf8");
  const start = ci.indexOf("\n  mcp-registry:\n");
  const next = ci.slice(start + 1).search(/\n {2}[a-z][a-z0-9_-]*:\n/);
  // Comment lines dropped: a step turned into a comment must not pass.
  const job = ci
    .slice(start, start + 1 + next)
    .split("\n")
    .filter((l) => !/^\s*#/.test(l))
    .join("\n");

  it("waits for npm to serve the tagged version before it publishes", () => {
    expect(start).toBeGreaterThan(0);
    const waitAt = job.indexOf('node scripts/await-npm-version.mjs "${GITHUB_REF_NAME#v}"');
    const publishAt = job.indexOf('"$RUNNER_TEMP/mcp-publisher" publish');
    expect(waitAt).toBeGreaterThan(0);
    expect(publishAt).toBeGreaterThan(waitAt);
  });

  it("waits for the mcpName package.json declares, which server.json names", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    const srv = JSON.parse(fs.readFileSync(path.join(ROOT, "server.json"), "utf8"));
    expect(pkg.mcpName).toBe(MCP_NAME);
    expect(srv.name).toBe(pkg.mcpName);
  });
});
