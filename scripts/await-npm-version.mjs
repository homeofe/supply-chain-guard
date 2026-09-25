// await-npm-version.mjs - wait until the npm registry serves one exact version
// of this package, carrying the mcpName the MCP Registry looks for.
//
// Usage (the mcp-registry job in .github/workflows/ci.yml):
//   node scripts/await-npm-version.mjs <version>
//
// WHY THIS EXISTS. The MCP Registry verifies that the io.github.homeofe/* name
// owns the npm package by reading `mcpName` from the PUBLISHED package.json of
// this exact version. The mcp-registry job starts seconds after `npm publish`,
// and the registry and its CDN can answer 404 for a new version for a while.
// Publishing into that window fails the job because npm has not caught up, not
// because anything is wrong. This waits until the version is served with the
// expected mcpName, for a bounded time, and names the last answer if it gives
// up.
//
// What it waits for and what it does not: a 404, another error status and a
// request that throws are all "not yet" and are retried. A document that IS
// served with another mcpName is an answer, not a delay, and fails at once.
//
// It checks what this runner sees. The MCP Registry reads npm from its own
// network, so this narrows the window rather than closing it. A job that still
// fails published nothing and can be re-run.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PACKAGE = "supply-chain-guard";
const REGISTRY = "https://registry.npmjs.org";
const sleep = (ms) => (ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

export async function awaitNpmVersion(
  version,
  { mcpName, fetchImpl = fetch, retryDelayMs = 15_000, attempts = 20 } = {},
) {
  if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) throw new Error(`not a release version: ${version}`);
  if (typeof mcpName !== "string" || mcpName === "") throw new Error("no mcpName to wait for");
  const url = `${REGISTRY}/${PACKAGE}/${version}`;
  let last = "";
  for (let i = 0; i < attempts; i++) {
    let doc;
    try {
      const res = await fetchImpl(url);
      if (res.ok) doc = await res.json();
      else last = `status ${res.status}`;
    } catch (err) {
      last = `error: ${err instanceof Error ? err.message : err}`;
    }
    if (doc !== undefined) {
      if (doc?.version === version && doc?.mcpName === mcpName) return { attempts: i + 1 };
      throw new Error(
        `npm serves ${PACKAGE}@${version} as version ${doc?.version} with mcpName ${doc?.mcpName}, ` +
          `not ${mcpName}; the MCP Registry would refuse it`,
      );
    }
    if (i < attempts - 1) await sleep(retryDelayMs);
  }
  throw new Error(`npm did not serve ${PACKAGE}@${version} after ${attempts} attempts (last ${last})`);
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  const [version] = process.argv.slice(2);
  try {
    const { mcpName } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    const { attempts } = await awaitNpmVersion(version, { mcpName });
    console.log(`npm serves ${PACKAGE}@${version} with mcpName ${mcpName} (attempt ${attempts})`);
  } catch (err) {
    console.error(`::error title=npm version::${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}
