import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

/**
 * Regression tests for the em-dash SCOPE checker (scripts/check-em-dash-scope.mjs).
 *
 * Why this exists: https://github.com/homeofe/supply-chain-guard/issues/178. The
 * repository held 77 em dashes across 17 files while the `forbidden-patterns`
 * gate reported "no matches" and exited 0 on every pull request, inside a
 * required status check. Nothing was broken and nothing lied. The `em-dash`
 * rule's `include` list named six pathspecs; those six matched none of the 17
 * files; "no matches" was the truthful answer to the question the rule actually
 * asked.
 *
 * That defect is invisible to the content gate by construction, because a gate
 * cannot report on files it was never pointed at. So the guard against it is a
 * separate question, asked here: does the rule's scope still cover the
 * repository? The first test below is the one that goes red if the scope ever
 * narrows again. The rest pin the checker's own verdicts, so that a green first
 * test means the checker still knows how to say no.
 *
 * Exit codes are asserted EXACTLY, never merely as non-zero, because the whole
 * failure class here is a check that returns the wrong kind of answer: 0 means
 * covered, 1 means a tracked file is uncovered and unexplained, 2 means the
 * question could not be answered at all.
 */
describe("em-dash rule scope", () => {
  const repoRoot = path.resolve(__dirname, "..", "..");
  const checker = path.join(repoRoot, "scripts", "check-em-dash-scope.mjs");

  /** Run the checker against `cwd`'s tree and return its exit code plus output. */
  const run = (scriptPath: string): { status: number; out: string } => {
    const res = spawnSync(process.execPath, [scriptPath], { encoding: "utf8" });
    return { status: res.status ?? -1, out: `${res.stdout ?? ""}${res.stderr ?? ""}` };
  };

  it("covers every tracked file in this repository", () => {
    // DELETE THE "*" ENTRY FROM the em-dash rule's `include` array in
    // aahp.config.json TO TURN THIS RED. Replacing it with a list of specific
    // pathspecs, which is what the rule carried before 2026-08-22, reddens it
    // the same way and is the exact shape of issue 178.
    const { status, out } = run(checker);
    expect(out).toContain("0 uncovered");
    expect(status).toBe(0);
  });

  describe("fixture trees", () => {
    let tmp: string;

    /**
     * A throwaway git tree shaped like this repository: a file the rule covers,
     * a file it could miss, the binary asset and the verbatim handoff archive
     * that SCOPE_EXCEPTIONS names. The checker resolves its repo root as
     * dirname(script)/.., so a copy of the script at <tmp>/scripts/ makes <tmp>
     * a complete, isolated fixture.
     */
    const writeConfig = (rule: Record<string, unknown>): void => {
      fs.writeFileSync(
        path.join(tmp, "aahp.config.json"),
        JSON.stringify({ forbiddenPatterns: [{ id: "em-dash", pattern: "\\u2014", flags: "g", ...rule }] }, null, 2),
      );
      spawnSync("git", ["-C", tmp, "add", "-A"], { encoding: "utf8" });
    };

    const fixtureChecker = (): string => path.join(tmp, "scripts", "check-em-dash-scope.mjs");

    beforeEach(() => {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-em-dash-scope-"));
      for (const dir of ["scripts", "src", "assets", path.join(".ai", "handoff")]) {
        fs.mkdirSync(path.join(tmp, dir), { recursive: true });
      }
      fs.copyFileSync(checker, fixtureChecker());
      fs.writeFileSync(path.join(tmp, "README.md"), "prose\n");
      fs.writeFileSync(path.join(tmp, "CHANGELOG.md"), "history\n");
      fs.writeFileSync(path.join(tmp, "src", "scanner.ts"), "export const x = 1;\n");
      fs.writeFileSync(path.join(tmp, "assets", "demo.gif"), Buffer.from([0x47, 0x49, 0x46, 0x38]));
      fs.writeFileSync(path.join(tmp, ".ai", "handoff", "LOG-ARCHIVE.md"), "archived\n");
      spawnSync("git", ["-C", tmp, "init", "-q"], { encoding: "utf8" });
      spawnSync("git", ["-C", tmp, "add", "-A"], { encoding: "utf8" });
    });

    afterEach(() => {
      fs.rmSync(tmp, { recursive: true, force: true });
    });

    it("exits 0 when the scope is opt-out and every exclusion is explained", () => {
      writeConfig({ include: ["*"], exclude: ["assets/demo.gif", ".ai/handoff/LOG-ARCHIVE.md"] });
      const { status, out } = run(fixtureChecker());
      expect(out).toContain("0 uncovered");
      expect(status).toBe(0);
    });

    it("exits 1 when an opt-in include list leaves a tracked file uncovered", () => {
      // The pre-2026-08-22 shape: an include list that names files rather than
      // the tree, so src/scanner.ts and CHANGELOG.md are outside the rule and
      // nothing says why.
      writeConfig({
        include: ["README.md", "assets/demo.gif", ".ai/handoff/LOG-ARCHIVE.md"],
        exclude: ["assets/demo.gif", ".ai/handoff/LOG-ARCHIVE.md"],
      });
      const { status, out } = run(fixtureChecker());
      expect(out).toContain("src/scanner.ts");
      expect(out).toContain("CHANGELOG.md");
      expect(status).toBe(1);
    });

    it("exits 2 on an exclude entry that subtracts nothing, the inert-line shape from issue 178", () => {
      writeConfig({
        include: ["README.md", "assets/demo.gif", ".ai/handoff/LOG-ARCHIVE.md"],
        exclude: ["assets/demo.gif", ".ai/handoff/LOG-ARCHIVE.md", "CHANGELOG.md"],
      });
      const { status, out } = run(fixtureChecker());
      expect(out).toContain("subtracts nothing");
      expect(status).toBe(2);
    });

    it("exits 2 when the rule states no include list, rather than inheriting the CLI default", () => {
      writeConfig({ exclude: ["assets/demo.gif", ".ai/handoff/LOG-ARCHIVE.md"] });
      const { status, out } = run(fixtureChecker());
      expect(out).toContain("no explicit non-empty include list");
      expect(status).toBe(2);
    });

    it("exits 2 on an include pathspec that has stopped matching", () => {
      writeConfig({ include: ["*", "docs/*.md"], exclude: ["assets/demo.gif", ".ai/handoff/LOG-ARCHIVE.md"] });
      const { status, out } = run(fixtureChecker());
      expect(out).toContain("matches no tracked file");
      expect(status).toBe(2);
    });
  });
});
