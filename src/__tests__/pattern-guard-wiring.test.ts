import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  FILE_PATTERNS,
  INFOSTEALER_PATTERNS,
  C2_EXTENDED_PATTERNS,
  SECRETS_PATTERNS,
  CAMPAIGN_PATTERNS_V2,
  OBFUSCATION_PATTERNS_V2,
  PROMPT_INJECTION_PATTERNS,
  isPatternApplicableToFile,
  isPatternMatchAccepted,
} from "../patterns.js";

/**
 * WIRING GUARANTEE.
 *
 * The PatternEntry arrays are iterated by six different scanners: the directory
 * scan, npm, PyPI, VS Code extensions, Dockerfiles and config files. A guard
 * honoured in only some of them is worse than no guard, because the same file
 * then produces different verdicts depending on which entry point looked at it -
 * and that difference is invisible until a user reports it.
 *
 * `requiresInFile` shipped honoured in exactly one loop. These tests exist so
 * that cannot happen again: any new pattern loop that forgets the guard fails
 * the build here rather than in someone's CI months later.
 */
describe("pattern guard wiring", () => {
  const srcDir = path.resolve(__dirname, "..");

  /** Source files that iterate a shared PatternEntry array. */
  const consumers = [
    "scanner.ts",
    "npm-scanner.ts",
    "pypi-scanner.ts",
    "vscode-scanner.ts",
    "dockerfile-scanner.ts",
    "config-scanner.ts",
  ];

  it.each(consumers)("%s honours the file-level guard", (file) => {
    const source = fs.readFileSync(path.join(srcDir, file), "utf8");
    // scanner.ts applies the guard inline (it already destructures the field);
    // the others call the shared helper. Either is acceptable, absence is not.
    const honoured =
      source.includes("isPatternApplicableToFile") ||
      source.includes("pattern.requiresInFile");
    expect(honoured, `${file} iterates patterns without applying requiresInFile`).toBe(true);
  });

  it.each(consumers)("%s honours the value-level guard", (file) => {
    const source = fs.readFileSync(path.join(srcDir, file), "utf8");
    expect(source.includes("isPatternMatchAccepted"), file).toBe(true);
  });

  /**
   * Files that iterate patterns but are exempt, because they do not scan FILE
   * content at all: both match PROMPT_INJECTION_PATTERNS against a string parsed
   * out of a config or workflow document, where a file-level corroboration guard
   * has no meaning. The exemption is only safe while those patterns declare no
   * guards, which the test below enforces.
   */
  const exempt = ["agentic-workflow-scanner.ts", "mcp-scanner.ts"];

  it("every pattern loop is covered by this test's consumer list", () => {
    // If a NEW file starts iterating pattern arrays, it must be added above.
    // Without this, the wiring test silently stops covering the codebase.
    const files = fs
      .readdirSync(srcDir)
      .filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts"));

    const iterators = files.filter((f) => {
      if (f === "patterns.ts" || f === "types.ts") return false;
      const source = fs.readFileSync(path.join(srcDir, f), "utf8");
      // A loop over one of the shared exported arrays.
      return /for \(const \w+ of (?:FILE_PATTERNS|INFOSTEALER_PATTERNS|C2_EXTENDED_PATTERNS|SECRETS_PATTERNS|CAMPAIGN_PATTERNS|CAMPAIGN_PATTERNS_V2|OBFUSCATION_PATTERNS_V2|OBFUSCATION_V3_PATTERNS|IAC_PATTERNS|PROVENANCE_PATTERNS|PROMPT_INJECTION_PATTERNS|BEACON_MINER_PATTERNS|DOCKERFILE_PATTERNS|CONFIG_PATTERNS|EXTENSION_DANGER_PATTERNS|OBFUSCATION_PATTERNS|PYPI_FILE_PATTERNS|PYPI_INSTALL_HOOK_PATTERNS)\)/.test(
        source,
      );
    });

    expect([...iterators].sort()).toEqual([...consumers, ...exempt].sort());
  });

  it("the exempt scanners' patterns declare no guards to skip", () => {
    // The moment a PROMPT_INJECTION rule gains a valueFilter or requiresInFile,
    // the exemption above becomes a silent hole and this fails.
    for (const p of PROMPT_INJECTION_PATTERNS) {
      expect(p.requiresInFile, `${p.rule} needs a guard the exempt scanners skip`).toBeUndefined();
      expect(p.valueFilter, `${p.rule} needs a guard the exempt scanners skip`).toBeUndefined();
    }
  });

  describe("the guard helper itself", () => {
    it("passes patterns that declare no file-level requirement", () => {
      expect(isPatternApplicableToFile({}, "anything")).toBe(true);
    });

    it("gates on the whole file, not a single line", () => {
      const pattern = { requiresInFile: /fetch\s*\(/ };
      expect(isPatternApplicableToFile(pattern, "const a = 1;\nfetch(url);\n")).toBe(true);
      expect(isPatternApplicableToFile(pattern, "const a = 1;\nconst b = 2;\n")).toBe(false);
    });

    it("leaves the value-level guard independent", () => {
      const match = ["AKIAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA"] as unknown as RegExpMatchArray;
      expect(
        isPatternMatchAccepted({ valueFilter: (v) => new Set(v).size >= 8 }, match),
      ).toBe(false);
    });
  });

  describe("rules that rely on the guard actually declare it", () => {
    const all = [
      ...FILE_PATTERNS,
      ...INFOSTEALER_PATTERNS,
      ...C2_EXTENDED_PATTERNS,
      ...SECRETS_PATTERNS,
      ...CAMPAIGN_PATTERNS_V2,
      ...OBFUSCATION_PATTERNS_V2,
    ];

    // These were the measured false positives: each fired on ordinary code and
    // is now corroboration-gated. Losing the guard reopens the false positive.
    const guarded = [
      "SHAI_HULUD_WORM",
      "SHAI_HULUD_CRED_STEAL",
      "DEAD_DROP_GIST",
      "PROXY_HANDLER_TRAP",
      "DROPPER_TEMP_EXEC",
    ];

    it.each(guarded)("%s declares requiresInFile", (rule) => {
      const entry = all.find((p) => p.rule === rule);
      expect(entry, `${rule} not found`).toBeDefined();
      expect(entry!.requiresInFile, `${rule} lost its file-level guard`).toBeDefined();
    });

    it("SECRETS_AWS_KEY keeps its distinct-character value guard", () => {
      const entry = all.find((p) => p.rule === "SECRETS_AWS_KEY");
      expect(entry?.valueFilter).toBeDefined();
      // Padded, repetitive body from a WASM blob: rejected.
      expect(entry!.valueFilter!("AAB0AAAAAAAAAKMA")).toBe(false);
      // Real-looking random body: accepted.
      expect(entry!.valueFilter!("7RJ4KQ2XZ9M3PLWD")).toBe(true);
    });
  });
});
