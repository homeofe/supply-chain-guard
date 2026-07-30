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

function parseSourceUnit(file: string, code: string): SourceUnit {
  return {
    file,
    code,
    ast: parse(code, {
      sourceType: "module",
      plugins: ["typescript"],
    }) as unknown as AstNode,
  };
}

function productionSources(srcDir: string): SourceUnit[] {
  return fs
    .readdirSync(srcDir)
    .filter((file) => file.endsWith(".ts") && !file.endsWith(".d.ts"))
    .sort()
    .map((file) =>
      parseSourceUnit(file, fs.readFileSync(path.join(srcDir, file), "utf8")));
}

function identifierName(node: unknown): string | undefined {
  if (!isNode(node) || node.type !== "Identifier") return undefined;
  return typeof node.name === "string" ? node.name : undefined;
}

function unwrapExpression(node: unknown): AstNode | undefined {
  let current = isNode(node) ? node : undefined;
  while (
    current &&
    [
      "ChainExpression",
      "ParenthesizedExpression",
      "TSAsExpression",
      "TSSatisfiesExpression",
      "TSNonNullExpression",
      "TypeCastExpression",
    ].includes(current.type) &&
    isNode(current.expression)
  ) {
    current = current.expression;
  }
  return current;
}

function memberPropertyName(node: unknown): string | undefined {
  const member = unwrapExpression(node);
  if (
    !member ||
    (member.type !== "MemberExpression" && member.type !== "OptionalMemberExpression")
  ) {
    return undefined;
  }
  const property = unwrapExpression(member.property);
  if (!property) return undefined;
  if (property.type === "Identifier") return identifierName(property);
  if (property.type === "StringLiteral" && typeof property.value === "string") {
    return property.value;
  }
  return undefined;
}

function isCallLike(node: unknown): node is AstNode {
  const expression = unwrapExpression(node);
  return expression?.type === "CallExpression" ||
    expression?.type === "OptionalCallExpression";
}

function memberObject(node: unknown): AstNode | undefined {
  const member = unwrapExpression(node);
  if (
    !member ||
    (member.type !== "MemberExpression" && member.type !== "OptionalMemberExpression")
  ) {
    return undefined;
  }
  return unwrapExpression(member.object);
}

/** Resolve a callable reference through wrappers used by transpiled code. */
function callableReferenceName(node: unknown): string | undefined {
  const expression = unwrapExpression(node);
  if (!expression) return undefined;

  if (expression.type === "SequenceExpression") {
    const expressions = Array.isArray(expression.expressions)
      ? expression.expressions
      : [];
    return callableReferenceName(expressions.at(-1));
  }

  const direct = identifierName(expression);
  if (direct) return direct;

  if (
    expression.type === "MemberExpression" ||
    expression.type === "OptionalMemberExpression"
  ) {
    const property = memberPropertyName(expression);
    if (["call", "apply", "bind"].includes(property ?? "")) {
      return callableReferenceName(memberObject(expression));
    }
    return property;
  }

  if (isCallLike(expression)) {
    const callee = unwrapExpression(expression.callee);
    if (memberPropertyName(callee) === "bind") {
      return callableReferenceName(memberObject(callee));
    }
  }

  return undefined;
}

function callableInvocationName(node: unknown): string | undefined {
  return callableReferenceName(node);
}

function invocationArguments(node: AstNode): unknown[] {
  const args = Array.isArray(node.arguments) ? node.arguments : [];
  const callee = unwrapExpression(node.callee);
  const adapter = memberPropertyName(callee);

  if (adapter === "call" || adapter === "bind") return args.slice(1);
  if (adapter === "apply") {
    const applied = unwrapExpression(args[1]);
    return applied?.type === "ArrayExpression" && Array.isArray(applied.elements)
      ? applied.elements
      : args.slice(1);
  }

  // Immediate invocation of a bound callable: fn.bind(thisArg, preset)(rest).
  if (isCallLike(callee)) {
    const boundCallee = unwrapExpression(callee.callee);
    if (memberPropertyName(boundCallee) === "bind") {
      const boundArgs = Array.isArray(callee.arguments)
        ? callee.arguments.slice(1)
        : [];
      return [...boundArgs, ...args];
    }
  }

  return args;
}

function collectCallableAliases(unit: SourceUnit, original: string): Set<string> {
  const aliases = new Set([original]);
  const nodes: AstNode[] = [];
  const collect = (node: AstNode): void => {
    nodes.push(node);
    forEachChild(node, collect);
  };
  collect(unit.ast);

  let changed = true;
  while (changed) {
    changed = false;
    for (const node of nodes) {
      if (node.type === "ImportSpecifier") {
        const imported = callableReferenceName(node.imported);
        const local = identifierName(node.local);
        if (imported === original && local && !aliases.has(local)) {
          aliases.add(local);
          changed = true;
        }
      }
      if (node.type === "VariableDeclarator") {
        const local = identifierName(node.id);
        const source = callableReferenceName(node.init);
        if (local && source && aliases.has(source) && !aliases.has(local)) {
          aliases.add(local);
          changed = true;
        }
        if (isNode(node.id) && node.id.type === "ObjectPattern") {
          for (const property of Array.isArray(node.id.properties) ? node.id.properties : []) {
            if (!isNode(property) || property.type !== "ObjectProperty") continue;
            const imported = callableReferenceName(property.key);
            const bound = identifierName(property.value);
            if (imported === original && bound && !aliases.has(bound)) {
              aliases.add(bound);
              changed = true;
            }
          }
        }
      }
      if (node.type === "AssignmentExpression") {
        const local = identifierName(node.left);
        const source = callableReferenceName(node.right);
        if (local && source && aliases.has(source) && !aliases.has(local)) {
          aliases.add(local);
          changed = true;
        }
      }
    }
  }
  return aliases;
}
function containsPatternProperty(node: unknown): boolean {
  const root = unwrapExpression(node);
  if (!root) return false;
  let found = false;
  const visit = (candidate: AstNode): void => {
    if (memberPropertyName(candidate) === "pattern") found = true;
    if (!found) forEachChild(candidate, visit);
  };
  visit(root);
  return found;
}

function directAliasName(
  node: unknown,
  aliases: ReadonlySet<string>,
): string | undefined {
  const name = identifierName(unwrapExpression(node));
  return name && aliases.has(name) ? name : undefined;
}

function patternPropertyBindingName(node: unknown): string | undefined {
  if (!isNode(node) || node.type !== "ObjectProperty") return undefined;
  const key = unwrapExpression(node.key);
  const keyName = identifierName(key) ??
    (key?.type === "StringLiteral" && typeof key.value === "string"
      ? key.value
      : undefined);
  if (keyName !== "pattern") return undefined;

  const value = unwrapExpression(node.value);
  if (value?.type === "AssignmentPattern") {
    return identifierName(value.left);
  }
  return identifierName(value);
}

/**
 * Track local strings sourced from PatternEntry.pattern. This intentionally
 * keeps a name tainted after reassignment: the wiring test is a conservative
 * guard, not a control-flow engine, and must not let an overwrite hide a bypass.
 */
function collectPatternSourceAliases(unit: SourceUnit): Set<string> {
  const aliases = new Set<string>();
  const nodes: AstNode[] = [];
  const collect = (node: AstNode): void => {
    nodes.push(node);
    forEachChild(node, collect);
  };
  collect(unit.ast);

  const sourceReaches = (node: unknown): boolean =>
    containsPatternProperty(node) || directAliasName(node, aliases) !== undefined;
  const collectPatternBinding = (node: unknown): boolean => {
    if (!isNode(node) || node.type !== "ObjectPattern") return false;
    let changed = false;
    for (const property of Array.isArray(node.properties) ? node.properties : []) {
      const name = patternPropertyBindingName(property);
      if (name && !aliases.has(name)) {
        aliases.add(name);
        changed = true;
      }
    }
    return changed;
  };

  let changed = true;
  while (changed) {
    changed = false;
    for (const node of nodes) {
      if (node.type === "VariableDeclarator") {
        const local = identifierName(node.id);
        if (local && sourceReaches(node.init) && !aliases.has(local)) {
          aliases.add(local);
          changed = true;
        }
        changed = collectPatternBinding(node.id) || changed;
      }
      if (node.type === "AssignmentExpression") {
        const local = identifierName(node.left);
        if (local && sourceReaches(node.right) && !aliases.has(local)) {
          aliases.add(local);
          changed = true;
        }
        changed = collectPatternBinding(node.left) || changed;
      }
    }
  }
  return aliases;
}

function containsPatternSource(
  node: unknown,
  aliases: ReadonlySet<string>,
): boolean {
  return containsPatternProperty(node) || directAliasName(node, aliases) !== undefined;
}

function directPatternRegexes(unit: SourceUnit): DirectPatternRegex[] {
  const found: DirectPatternRegex[] = [];
  const regexAliases = collectCallableAliases(unit, "RegExp");
  const patternSources = collectPatternSourceAliases(unit);

  const visit = (node: AstNode, functionName = "<module>"): void => {
    let scope = functionName;
    if (node.type === "FunctionDeclaration") {
      scope = identifierName(node.id) ?? scope;
    }

    const args = invocationArguments(node);
    if (
      ["CallExpression", "OptionalCallExpression", "NewExpression"].includes(node.type) &&
      regexAliases.has(callableInvocationName(node.callee) ?? "") &&
      args.some((argument) => containsPatternSource(argument, patternSources))
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
  const aliases = collectCallableAliases(unit, "matchPatternInContent");
  const visit = (node: AstNode): void => {
    const args = invocationArguments(node);
    if (
      (node.type === "CallExpression" || node.type === "OptionalCallExpression") &&
      aliases.has(callableInvocationName(node.callee) ?? "") &&
      args.length > 0
    ) {
      calls.push(unit.file);
    }
    forEachChild(node, visit);
  };
  visit(unit.ast);
  return calls;
}

function nodeSource(unit: SourceUnit, node: AstNode): string {
  const start = node.start ?? 0;
  const end = node.end ?? start;
  return unit.code.slice(start, end);
}

function isPatternCollectionType(source: string): boolean {
  return /\b(?:Readonly)?Array\s*<[\s\S]*\b(?:PatternEntry|InternalPatternEntry)\b/.test(source) ||
    /\b(?:PatternEntry|InternalPatternEntry)\b[\s\S]*\[\s*\]/.test(source);
}

function unwrapTypeNode(node: unknown): AstNode | undefined {
  let current = isNode(node) ? node : undefined;
  while (
    current &&
    ["TSTypeAnnotation", "TSParenthesizedType"].includes(current.type) &&
    isNode(current.typeAnnotation)
  ) {
    current = current.typeAnnotation;
  }
  return current;
}

function referencedTypeName(node: unknown): string | undefined {
  const typeNode = unwrapTypeNode(node);
  return typeNode?.type === "TSTypeReference"
    ? identifierName(typeNode.typeName)
    : undefined;
}

function localPatternCollectionTypeAliases(unit: SourceUnit): Set<string> {
  const declarations = new Map<string, AstNode>();
  const visit = (node: AstNode): void => {
    if (
      node.type === "TSTypeAliasDeclaration" &&
      identifierName(node.id) &&
      isNode(node.typeAnnotation)
    ) {
      declarations.set(identifierName(node.id)!, node.typeAnnotation);
    }
    forEachChild(node, visit);
  };
  visit(unit.ast);

  const aliases = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, annotation] of declarations) {
      const referenced = referencedTypeName(annotation);
      if (
        !aliases.has(name) &&
        (
          isPatternCollectionType(nodeSource(unit, annotation)) ||
          (referenced !== undefined && aliases.has(referenced))
        )
      ) {
        aliases.add(name);
        changed = true;
      }
    }
  }
  return aliases;
}

function isPatternCollectionAnnotation(
  unit: SourceUnit,
  annotation: AstNode,
  aliases: ReadonlySet<string>,
): boolean {
  const referenced = referencedTypeName(annotation);
  return isPatternCollectionType(nodeSource(unit, annotation)) ||
    (referenced !== undefined && aliases.has(referenced));
}

function patternArrayDeclarations(unit: SourceUnit): string[] {
  const names: string[] = [];
  const typeAliases = localPatternCollectionTypeAliases(unit);
  const visit = (node: AstNode): void => {
    if (node.type === "VariableDeclarator" && identifierName(node.id)) {
      const annotations: AstNode[] = [];
      if (isNode(node.id) && isNode(node.id.typeAnnotation)) {
        annotations.push(node.id.typeAnnotation);
      }

      let initializer = isNode(node.init) ? node.init : undefined;
      while (
        initializer &&
        ["TSAsExpression", "TSSatisfiesExpression"].includes(initializer.type)
      ) {
        if (isNode(initializer.typeAnnotation)) {
          annotations.push(initializer.typeAnnotation);
        }
        initializer = isNode(initializer.expression)
          ? initializer.expression
          : undefined;
      }

      if (
        annotations.some((annotation) =>
          isPatternCollectionAnnotation(unit, annotation, typeAliases)
        )
      ) {
        names.push(identifierName(node.id)!);
      }
    }
    forEachChild(node, visit);
  };
  visit(unit.ast);
  return names;
}
interface ValidatorAlias {
  presetArguments: unknown[];
}

function boundCallable(
  node: unknown,
): { target: string; presetArguments: unknown[] } | undefined {
  const expression = unwrapExpression(node);
  if (!isCallLike(expression)) return undefined;
  const callee = unwrapExpression(expression.callee);
  if (memberPropertyName(callee) !== "bind") return undefined;
  const target = callableReferenceName(memberObject(callee));
  if (!target) return undefined;
  const args = Array.isArray(expression.arguments) ? expression.arguments : [];
  return { target, presetArguments: args.slice(1) };
}

function collectValidatorAliases(unit: SourceUnit): Map<string, ValidatorAlias> {
  const aliases = new Map<string, ValidatorAlias>([
    ["validatePatternSet", { presetArguments: [] }],
  ]);
  const nodes: AstNode[] = [];
  const collect = (node: AstNode): void => {
    nodes.push(node);
    forEachChild(node, collect);
  };
  collect(unit.ast);

  const register = (
    local: string | undefined,
    source: unknown,
  ): boolean => {
    if (!local || aliases.has(local)) return false;

    const bound = boundCallable(source);
    if (bound) {
      const target = aliases.get(bound.target);
      if (!target) return false;
      aliases.set(local, {
        presetArguments: [
          ...target.presetArguments,
          ...bound.presetArguments,
        ],
      });
      return true;
    }

    const sourceName = callableReferenceName(source);
    const target = sourceName ? aliases.get(sourceName) : undefined;
    if (!target) return false;
    aliases.set(local, {
      presetArguments: [...target.presetArguments],
    });
    return true;
  };

  let changed = true;
  while (changed) {
    changed = false;
    for (const node of nodes) {
      if (node.type === "ImportSpecifier") {
        const imported = callableReferenceName(node.imported);
        if (imported === "validatePatternSet") {
          changed = register(identifierName(node.local), node.imported) ||
            changed;
        }
      }
      if (node.type === "VariableDeclarator") {
        changed = register(identifierName(node.id), node.init) || changed;
        if (isNode(node.id) && node.id.type === "ObjectPattern") {
          for (
            const property of Array.isArray(node.id.properties)
              ? node.id.properties
              : []
          ) {
            if (!isNode(property) || property.type !== "ObjectProperty") {
              continue;
            }
            const imported = callableReferenceName(property.key);
            if (imported === "validatePatternSet") {
              changed = register(
                identifierName(property.value),
                property.key,
              ) || changed;
            }
          }
        }
      }
      if (node.type === "AssignmentExpression") {
        changed = register(identifierName(node.left), node.right) || changed;
      }
    }
  }
  return aliases;
}

function validatedLocalSets(unit: SourceUnit): Set<string> {
  const names = new Set<string>();
  const aliases = collectValidatorAliases(unit);
  const visit = (node: AstNode): void => {
    const callee = unwrapExpression(node.callee);
    const adapter = memberPropertyName(callee);
    // Function.prototype.bind creates a callable; it does not execute it.
    if (
      (node.type === "CallExpression" || node.type === "OptionalCallExpression") &&
      adapter !== "bind"
    ) {
      const callable = callableInvocationName(node.callee);
      const alias = callable ? aliases.get(callable) : undefined;
      if (alias) {
        const effectiveArguments = [
          ...alias.presetArguments,
          ...invocationArguments(node),
        ];
        const patternSet = unwrapExpression(effectiveArguments[1]);
        const patternSetName = identifierName(patternSet);
        if (patternSetName) names.add(patternSetName);
      }
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

  describe("AST detector self-tests", () => {
    it("recognizes optional, sequence, call/apply/bind, and aliased RegExp forms", () => {
      const unit = parseSourceUnit("adversarial.ts", `
        const RegexAlias = globalThis.RegExp;
        const BoundRegex = RegExp.bind(globalThis);
        RegExp(entry.pattern);
        new globalThis.RegExp(entry["pattern"]);
        new RegexAlias(entry?.pattern);
        (0, RegExp)?.(entry.pattern);
        RegExp.call(null, entry.pattern);
        RegExp.apply(null, [entry.pattern]);
        BoundRegex(entry.pattern);
        RegExp.bind(null, entry.pattern);
      `);
      expect(directPatternRegexes(unit)).toHaveLength(8);
    });

    it("tracks locally extracted pattern sources through aliases and overwrites", () => {
      const unit = parseSourceUnit("adversarial.ts", `
        const direct = entry.pattern;
        const bracket = entry["pattern"];
        const alias = direct;
        let assigned = "safe";
        assigned = alias;
        const { pattern: destructured } = entry;
        let overwritten = entry.pattern;
        overwritten = "safe";
        const description = entry.description;
        const { name } = entry;
        new RegExp(bracket);
        RegExp(assigned);
        new globalThis.RegExp(destructured);
        new RegExp(overwritten);
        new RegExp(description);
        new RegExp(name);
      `);
      expect(directPatternRegexes(unit)).toHaveLength(4);
    });
    it("recognizes optional, sequence, call/apply/bind, and aliased matcher calls", () => {
      const unit = parseSourceUnit("adversarial.ts", `
        import { matchPatternInContent as run } from "./patterns.js";
        const memberAlias = engine["matchPatternInContent"];
        const bound = matchPatternInContent.bind(engine);
        run(entry, content);
        engine.matchPatternInContent(entry, content);
        memberAlias(entry, content);
        (0, run)?.(entry, content);
        matchPatternInContent.call(null, entry, content);
        matchPatternInContent.apply(null, [entry, content]);
        bound(entry, content);
        matchPatternInContent.bind(null, entry, content);
      `);
      expect(directEngineCalls(unit)).toHaveLength(8);
    });

    it("recognizes satisfies, assertion, and non-literal typed pattern tables", () => {
      const unit = parseSourceUnit("adversarial.ts", `
        const SATISFIED = [] satisfies PatternEntry[];
        const ASSERTED = [] as Array<Omit<PatternEntry, "name">>;
        const COMPUTED: ReadonlyArray<InternalPatternEntry> = makePatterns();
      `);
      expect(patternArrayDeclarations(unit).sort()).toEqual([
        "ASSERTED",
        "COMPUTED",
        "SATISFIED",
      ]);
    });

    it("resolves local PatternEntry type aliases but rejects ordinary aliases", () => {
      const unit = parseSourceUnit("adversarial.ts", `
        type PatternList = PatternEntry[];
        type PatternAlias = PatternList;
        type PatternAliasChain = PatternAlias;
        type OrdinaryList = string[];
        const DIRECT_ALIAS: PatternList = [];
        const CHAINED_ALIAS: PatternAliasChain = [];
        const ORDINARY_ALIAS: OrdinaryList = [];
      `);
      expect(patternArrayDeclarations(unit).sort()).toEqual([
        "CHAINED_ALIAS",
        "DIRECT_ALIAS",
      ]);
    });
    it("recognizes executed aliases, call/apply, and bound validators", () => {
      const unit = parseSourceUnit("adversarial.ts", `
        import { validatePatternSet as check } from "./patterns.js";
        const validatorAlias = validators["validatePatternSet"];
        const bound = validatePatternSet.bind(null);
        const nameBound = check.bind(null, "H");
        const fullyBound = validatorAlias.bind(null, "I", I);
        check("A", A);
        validators.validatePatternSet("B", B);
        validatorAlias("C", C);
        (0, check)?.("D", D);
        validatePatternSet.call(null, "E", E);
        validatePatternSet.apply(null, ["F", F]);
        bound("G", G);
        nameBound(H);
        fullyBound();
        validatePatternSet.bind(null, "J", J)();
      `);
      expect([...validatedLocalSets(unit)].sort()).toEqual([
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
      ]);
    });

    it("does not credit bare binds or derived arrays as validation", () => {
      const unit = parseSourceUnit("adversarial.ts", `
        const bare = validatePatternSet.bind(null, "BARE", BARE);
        validatePatternSet.bind(null, "INLINE_BARE", INLINE_BARE);
        validatePatternSet("DERIVED", DERIVED.slice(0, 0));
        validatePatternSet.call(null, "CALL_DERIVED", CALL_DERIVED.filter(Boolean));
        validatePatternSet.apply(null, ["APPLY_DERIVED", APPLY_DERIVED.map(copy)]);
        const boundDerived = validatePatternSet.bind(
          null,
          "BOUND_DERIVED",
          BOUND_DERIVED.slice(),
        );
        void bare;
        boundDerived();
      `);
      expect([...validatedLocalSets(unit)]).toEqual([]);
    });
  });

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
