import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

/**
 * Regression tests for the handoff staleness gate (scripts/aahp-dashboard.mjs).
 *
 * Why this exists: the gate embeds a Toolchain table listing every dependency
 * and its version straight from package.json. That made EVERY dependency bump
 * turn `npm run build` red on "Handoff docs are stale: DASHBOARD.md", and
 * dependabot cannot fix it because its PRs run with a read-only token and it
 * cannot run `handoff:refresh`. Every dependabot PR therefore arrived red and
 * needed a human to hand-pull the bump into a release commit.
 *
 * The table is now written truthfully but excluded from the staleness
 * COMPARISON. These tests pin both halves of that trade: a pure dependency bump
 * must pass, and every other kind of drift must still fail.
 *
 * The script resolves its repo root as `dirname(script)/..`, so a throwaway tree
 * with the script at <tmp>/scripts/ is a complete, isolated fixture.
 */
describe("handoff staleness gate", () => {
  const repoRoot = path.resolve(__dirname, "..", "..");
  let tmp: string;

  /** Run the gate in the fixture tree. Returns true when it passes. */
  const check = (): boolean => {
    try {
      execFileSync(process.execPath, [path.join(tmp, "scripts", "aahp-dashboard.mjs"), "--check"], {
        cwd: tmp,
        stdio: "pipe",
      });
      return true;
    } catch {
      return false;
    }
  };

  const refresh = (): void => {
    execFileSync(process.execPath, [path.join(tmp, "scripts", "aahp-dashboard.mjs")], {
      cwd: tmp,
      stdio: "pipe",
    });
  };

  const readDashboard = () => fs.readFileSync(path.join(tmp, ".ai", "handoff", "DASHBOARD.md"), "utf8");
  const writeDashboard = (s: string) =>
    fs.writeFileSync(path.join(tmp, ".ai", "handoff", "DASHBOARD.md"), s);

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "scg-handoff-"));
    fs.mkdirSync(path.join(tmp, "scripts"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "src", "__tests__"), { recursive: true });
    fs.mkdirSync(path.join(tmp, ".ai", "handoff"), { recursive: true });

    // The dashboard script shells out to aahp-manifest.sh (which sources
    // _aahp-lib.sh) to regenerate MANIFEST.json, so the fixture needs all three.
    for (const f of ["aahp-dashboard.mjs", "aahp-manifest.sh", "_aahp-lib.sh"]) {
      fs.copyFileSync(path.join(repoRoot, "scripts", f), path.join(tmp, "scripts", f));
    }
    fs.writeFileSync(
      path.join(tmp, "package.json"),
      JSON.stringify(
        {
          name: "fixture",
          version: "1.0.0",
          engines: { node: ">=20.0.0" },
          dependencies: { commander: "^14.0.3" },
          devDependencies: { typescript: "^7.0.2", vitest: "^4.1.10" },
        },
        null,
        2,
      ),
    );
    fs.writeFileSync(
      path.join(tmp, "tsconfig.json"),
      JSON.stringify({ compilerOptions: { types: ["node"] } }, null, 2),
    );
    fs.writeFileSync(path.join(tmp, "src", "alpha.ts"), "export const a = 1;\n");
    fs.writeFileSync(path.join(tmp, "src", "beta.ts"), "export const b = 2;\n");
    fs.writeFileSync(path.join(tmp, "src", "__tests__", "alpha.test.ts"), "// test\n");
    fs.writeFileSync(
      path.join(tmp, "CHANGELOG.md"),
      "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] - 2026-01-01\n\n### Added\n\n- initial\n",
    );

    refresh(); // generate a consistent baseline
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("passes on a freshly generated tree", () => {
    expect(check()).toBe(true);
  });

  it("passes when only a dependency version changed (the dependabot case)", () => {
    // Exactly what a dependabot PR looks like: package.json moves, the committed
    // DASHBOARD.md does not, and nothing regenerates it. This used to fail and is
    // the single reason every dependency PR in this repo arrived red.
    const pkgPath = path.join(tmp, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    pkg.devDependencies.typescript = "^7.9.9";
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));

    expect(check()).toBe(true);
  });

  it("still FAILS when a dependency is added or removed", () => {
    // Deliberate boundary. Only the version COLUMN is ungated, not the row set:
    // adding or removing a dependency changes what the project depends on, which
    // is a human decision and belongs in the gated state. Dependabot never does
    // this - it only moves versions - so the recurring red-PR problem stays fixed
    // while a genuine change to the dependency set still demands a refresh.
    const pkgPath = path.join(tmp, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    pkg.devDependencies["@types/node"] = "^26.1.1";
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));

    expect(check()).toBe(false);
  });

  it("still FAILS when the project version drifts", () => {
    writeDashboard(readDashboard().replace(/1\.0\.0/g, "9.9.9"));
    expect(check()).toBe(false);
  });

  it("still FAILS when the source-module count drifts", () => {
    fs.writeFileSync(path.join(tmp, "src", "gamma.ts"), "export const g = 3;\n");
    expect(check()).toBe(false);
  });

  it("still FAILS when the test-file count drifts", () => {
    fs.writeFileSync(path.join(tmp, "src", "__tests__", "beta.test.ts"), "// test\n");
    expect(check()).toBe(false);
  });

  it("still FAILS when a handoff doc is hand-edited", () => {
    writeDashboard(readDashboard() + "\nhand-edited line\n");
    expect(check()).toBe(false);
  });

  it("writes the REAL dependency versions, it just does not gate them", () => {
    // The ungating is comparison-only. The generated doc must stay truthful, or
    // readers (and agents) would be handed a stale claim about the toolchain.
    const pkgPath = path.join(tmp, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    pkg.devDependencies.typescript = "^7.9.9";
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));

    refresh();
    expect(readDashboard()).toContain("| typescript | ^7.9.9 |");
  });
});
