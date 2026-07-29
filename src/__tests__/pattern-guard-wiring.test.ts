import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { parse } from "@babel/parser";
import {
  ALL_PATTERN_SETS,
  FILE_PATTERNS,
  INFOSTEALER_PATTERNS,
  C2_EXTENDED_PATTERNS,
  SECRETS_PATTERNS,
  CAMPAIGN_PATTERNS_V2,
  OBFUSCATION_PATTERNS_V2,
  isPatternMatchAccepted,
} from "../patterns.js";
import { isPatternApplicableToFile } from "../pattern-applicability.js";

interface AstNode {
  type: string;
  start?: number | null;
  end?: number | null;
  [key: string]: unknown;
}

interface SourceUnit {
  file: string;
  code: string;
  ast: AstNode;
}

interface DirectPatternRegex {
  file: string;
  functionName: string;
}

function isNode(value: unknown): value is AstNode {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as { type?: unknown }).type === "string";
}

function forEachChild(node: AstNode, visit: (child: AstNode) => void): void {
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isNode(item)) visit(item);
      }
    } else if (isNode(value)) {
      visit(value);
    }
  }
}

function productionSources(srcDir: string): SourceUnit[] {
  return fs
    .readdirSync(srcDir)
    .filter((file) => file.endsWith(".ts") && !file.endsWith(".d.ts"))
    .sort()
    .map((file) => {
      const code = fs.readFileSync(path.join(srcDir, file), "utf8");
      return {
        file,
        code,
        ast: parse(code, {
          sourceType: "module",
          plugins: ["typescript"],
        }) as unknown as AstNode,
      };
    });
}

function identifierName(node: unknown): string | undefined {
  if (!isNode(node) || node.type !== "Identifier") return undefined;
  return typeof node.name === "string" ? node.name : undefined;
}

function directPatternRegexes(unit: SourceUnit): DirectPatternRegex[] {
  const found: DirectPatternRegex[] = [];

  const visit = (node: AstNode, functionName = "<module>"): void => {
    let scope = functionName;
    if (node.type === "FunctionDeclaration") {
      scope = identifierName(node.id) ?? scope;
    }

    const args = Array.isArray(node.arguments) ? node.arguments : [];
    const firstArg = args[0];
    if (
      node.type === "NewExpression" &&
      identifierName(node.callee) === "RegExp" &&
      isNode(firstArg) &&
      (firstArg.type === "MemberExpression" || firstArg.type === "OptionalMemberExpression") &&
      identifierName(firstArg.property) === "pattern"
    ) {
      found.push({ file: unit.file, functionName: scope });
    }
    forEachChild(node, (child) => visit(child, scope));
  };

  visit(unit.ast);
  return found;
}

function directEngineCalls(unit: SourceUnit): string[] {
  const calls: string[] = [];
  const visit = (node: AstNode): void => {
    if (
      node.type === "CallExpression" &&
      identifierName(node.callee) === "matchPatternInContent"
    ) {
      calls.push(unit.file);
    }
    forEachChild(node, visit);
  };
  visit(unit.ast);
  return calls;
}

function patternArrayDeclarations(unit: SourceUnit): string[] {
  const names: string[] = [];
  const visit = (node: AstNode): void => {
    if (
      node.type === "VariableDeclarator" &&
      identifierName(node.id) &&
      isNode(node.init) &&
      node.init.type === "ArrayExpression" &&
      isNode(node.id) &&
      isNode(node.id.typeAnnotation)
    ) {
      const annotation = node.id.typeAnnotation;
      const start = annotation.start ?? 0;
      const end = annotation.end ?? start;
      if (/\b(?:PatternEntry|InternalPatternEntry)\b/.test(unit.code.slice(start, end))) {
        names.push(identifierName(node.id)!);
      }
    }
    forEachChild(node, visit);
  };
  visit(unit.ast);
  return names;
}

function validatedLocalSets(unit: SourceUnit): Set<string> {
  const names = new Set<string>();
  const visit = (node: AstNode): void => {
    const args = Array.isArray(node.arguments) ? node.arguments : [];
    if (
      node.type === "CallExpression" &&
      identifierName(node.callee) === "validatePatternSet" &&
      identifierName(args[1])
    ) {
      names.add(identifierName(args[1])!);
    }
    forEachChild(node, visit);
  };
  visit(unit.ast);
  return names;
}

/**
 * Wiring guarantee: production PatternEntry evaluation goes through one of two
 * explicit runners. `matchPatternInFile` applies every file guard, line spans,
 * value filters, and coverage reporting. `matchPatternInSemanticText` is for
 * agent-facing strings whose owning scanner already selected the file/field.
 */
describe("pattern guard wiring", () => {
  const srcDir = path.resolve(__dirname, "..");
  const sources = productionSources(srcDir);

  it("prohibits direct PatternEntry regex engines outside explicit specialized scanners", () => {
    const direct = sources.flatMap(directPatternRegexes);

    // Internal disclosure intentionally needs semantics the shared line-window
    // runner does not provide. InternalPatternEntry forbids spansLines and
    // requiresInFile at the type level.
    expect(direct).toEqual([
      { file: "internal-disclosure.ts", functionName: "scanInternalDisclosure" },
      { file: "patterns.ts", functionName: "matchPatternInContent" },
      { file: "patterns.ts", functionName: "validatePatternSet" },
      { file: "patterns.ts", functionName: "validatePatternSet" },
    ]);
  });

  it("keeps the low-level matcher behind the production wrapper", () => {
    const bypasses = sources.flatMap((unit) =>
      ["patterns.ts", "pattern-scanner.ts"].includes(unit.file)
        ? []
        : directEngineCalls(unit),
    );
    expect(bypasses).toEqual([]);
  });

  it("registers every typed pattern table for load-time validation", () => {
    const coreRegistered = new Set(ALL_PATTERN_SETS.map(([name]) => name));
    const missing: string[] = [];

    for (const unit of sources) {
      const declarations = patternArrayDeclarations(unit);
      const localRegistered = validatedLocalSets(unit);
      for (const name of declarations) {
        const registered = unit.file === "patterns.ts"
          ? coreRegistered.has(name)
          : localRegistered.has(name);
        if (!registered) missing.push(`${unit.file}:${name}`);
      }
    }

    expect(missing).toEqual([]);
  });

  describe("the central applicability contract", () => {
    it("passes patterns that declare no file-level requirement", () => {
      expect(isPatternApplicableToFile({}, "anything", "src/index.js")).toBe(true);
    });

    it("gates on whole-file corroboration, not one match line", () => {
      const pattern = { requiresInFile: /fetch\s*\(/ };
      expect(
        isPatternApplicableToFile(
          pattern,
          "const a = 1;\nfetch(url);\n",
          "src/index.js",
        ),
      ).toBe(true);
      expect(
        isPatternApplicableToFile(
          pattern,
          "const a = 1;\nconst b = 2;\n",
          "src/index.js",
        ),
      ).toBe(false);
    });

    it("leaves the value-level guard independent", () => {
      const match = [
        "AKIAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAA",
      ] as unknown as RegExpMatchArray;
      expect(
        isPatternMatchAccepted(
          { valueFilter: (value) => new Set(value).size >= 8 },
          match,
        ),
      ).toBe(false);
    });
  });

  describe("rules that rely on corroboration keep it", () => {
    const all = [
      ...FILE_PATTERNS,
      ...INFOSTEALER_PATTERNS,
      ...C2_EXTENDED_PATTERNS,
      ...SECRETS_PATTERNS,
      ...CAMPAIGN_PATTERNS_V2,
      ...OBFUSCATION_PATTERNS_V2,
    ];

    const guarded = [
      "SHAI_HULUD_WORM",
      "SHAI_HULUD_CRED_STEAL",
      "DEAD_DROP_GIST",
      "PROXY_HANDLER_TRAP",
      "DROPPER_TEMP_EXEC",
    ];

    it.each(guarded)("%s declares a whole-file corroboration guard", (rule) => {
      const entry = all.find((pattern) => pattern.rule === rule);
      expect(entry, `${rule} not found`).toBeDefined();
      expect(
        entry!.requiresInFile ?? entry!.requiresInFileMatcher,
        `${rule} lost its file-level guard`,
      ).toBeDefined();
    });

    it("SECRETS_AWS_KEY keeps its distinct-character value guard", () => {
      const entry = all.find((pattern) => pattern.rule === "SECRETS_AWS_KEY");
      expect(entry?.valueFilter).toBeDefined();
      expect(entry!.valueFilter!("AAB0AAAAAAAAAKMA")).toBe(false);
      expect(entry!.valueFilter!("7RJ4KQ2XZ9M3PLWD")).toBe(true);
    });
  });
});
