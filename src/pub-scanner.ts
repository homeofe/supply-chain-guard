/**
 * Dart / Flutter (pub) dependency scanner.
 *
 * Resolves the packages a Dart or Flutter project pulls from pub.dev and
 * matches them against `pub:<name>[@version]` feed entries.
 *
 *   - `pubspec.lock`: every `source: hosted` package with its exact locked
 *     version, using `description.name` (the real registry name, which can
 *     differ from the map key) and only when `description.url` is pub.dev.
 *   - `pubspec.yaml`: `dependencies`, `dev_dependencies` and
 *     `dependency_overrides`. Only an exact version pin counts as a version;
 *     a range (`^1.0.0`) leaves it unknown, so only a whole-package entry can
 *     fire there.
 *
 * A package hosted elsewhere is a different registry's package that merely
 * shares the name, and git, path and sdk sources have no pub identity, so
 * none of them is looked up.
 *
 * Both files are machine-shaped YAML with fixed nesting, read here by
 * indentation rather than with a general YAML parser.
 */

import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { stripHashComment } from "./text-lines.js";

export interface PubPackage {
  name: string;
  version: string | undefined;
  line: number;
}

// pub.flutter-io.cn is the China mirror that the Flutter docs ("Using
// Flutter in China") name for PUB_HOSTED_URL; it serves pub.dev's packages
// unchanged, so a package locked through it is the pub.dev package.
const PUB_HOSTS = new Set(["https://pub.dev", "https://pub.dartlang.org", "https://pub.flutter-io.cn"]);
/** pub names are lowercase_with_underscores by rule. */
const PUB_NAME = /^[a-z_][a-z0-9_]*$/;
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const DEPENDENCY_SECTIONS = new Set(["dependencies", "dev_dependencies", "dependency_overrides"]);

/**
 * Check if a file declares or locks pub packages.
 */
export function isPubFile(relativePath: string): boolean {
  const basename = relativePath.replace(/\\/g, "/").split("/").pop() ?? "";
  return basename === "pubspec.lock" || basename === "pubspec.yaml";
}

interface Line {
  indent: number;
  key: string;
  value: string;
  line: number;
}

/** `key: value` lines with their indentation; comments and blanks dropped. */
function readLines(content: string): Line[] {
  const out: Line[] = [];
  content.split(/\r?\n/).forEach((raw, i) => {
    const text = stripHashComment(raw);
    if (!text.trim() || text.trim().startsWith("#")) return;
    // Greedy up to the first colon, trimmed after: a lazy key followed by
    // \s*: is quadratic on a colon-free line with a long whitespace run.
    const m = /^([ \t]*)([^:\s][^:]*):[ \t]*(.*)$/.exec(text);
    if (!m) return;
    const value = m[3]!.trim().replace(/^&[\w-]+(?:[ \t]+|$)/, "");
    out.push({ indent: m[1]!.length, key: unquote(m[2]!.trim()), value: unquote(value), line: i + 1 });
  });
  return out;
}

function unquote(value: string): string {
  const m = /^(["'])(.*)\1$/.exec(value);
  return m ? m[2]! : value;
}

/** The lines nested under entry `i` (strictly deeper indentation). */
function childrenOf(lines: Line[], i: number): Line[] {
  const base = lines[i]!.indent;
  const out: Line[] = [];
  for (let j = i + 1; j < lines.length && lines[j]!.indent > base; j++) out.push(lines[j]!);
  return out;
}

function extractLock(lines: Line[]): PubPackage[] {
  const out: PubPackage[] = [];
  const top = lines.findIndex((l) => l.indent === 0 && l.key === "packages");
  if (top < 0) return out;
  const pkgIndent = lines[top + 1]?.indent;
  if (pkgIndent === undefined || pkgIndent === 0) return out;
  for (let i = top + 1; i < lines.length && lines[i]!.indent > 0; i++) {
    const entry = lines[i]!;
    if (entry.indent !== pkgIndent) continue;
    const body = childrenOf(lines, i);
    const field = (key: string, indent: number) => body.find((l) => l.key === key && l.indent === indent)?.value;
    const fieldIndent = body[0]?.indent ?? pkgIndent + 2;
    // The description map's children are the only lines nested deeper than
    // the entry's own fields. Requiring a pub.dev url there is also what
    // excludes git (its url is the git host), path and sdk (no url) sources.
    const desc = body.filter((l) => l.indent > fieldIndent);
    const url = desc.find((l) => l.key === "url")?.value;
    // description.name is what pub downloads; the map key is only a label, and
    // a lockfile is target-controlled, so the key is never trusted over it.
    const name = desc.find((l) => l.key === "name")?.value ?? entry.key;
    const version = field("version", fieldIndent);
    if (!url || !isPubHost(url)) continue;
    if (!PUB_NAME.test(name)) continue;
    out.push({ name, version: version && EXACT_VERSION.test(version) ? version : undefined, line: entry.line });
  }
  return out;
}

type Field = Pick<Line, "key" | "value">;

/**
 * Pairs of a one-line flow map `{a: b, c: {d: e}}`, nested maps flattened
 * into the list the way the block form's descendant lines are. Commas are
 * split at depth 0 only, and nesting is followed two levels (enough for
 * `hosted: {url: ...}` / `git: {url: ...}`) so the work stays linear.
 */
/** The top-level `key: value` pairs of a `{...}` flow map. */
function topLevelPairs(text: string): Array<[string, string]> {
  const inner = text.slice(1, -1);
  const parts: string[] = [];
  let level = 0;
  let start = 0;
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === "{" || c === "[") level++;
    else if (c === "}" || c === "]") level--;
    else if (c === "," && level === 0) {
      parts.push(inner.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(inner.slice(start));
  const out: Array<[string, string]> = [];
  for (const part of parts) {
    const colon = part.indexOf(":");
    if (colon < 0) continue;
    out.push([unquote(part.slice(0, colon).trim()), unquote(part.slice(colon + 1).trim())]);
  }
  return out;
}

function flowPairs(text: string, depth = 0): Field[] {
  const out: Field[] = [];
  for (const [key, value] of topLevelPairs(text)) {
    if (value.startsWith("{") && value.endsWith("}")) {
      out.push({ key, value: "" });
      // A loop, not a spread: a spread of an input-sized array overflows the stack.
      if (depth < 2) for (const field of flowPairs(value, depth + 1)) out.push(field);
    } else {
      out.push({ key, value });
    }
  }
  return out;
}

/** Net `{` minus `}` in text, ignoring quoted strings. */
function braceDepth(text: string): number {
  let depth = 0;
  let quote = "";
  for (const ch of text) {
    if (quote) {
      if (ch === quote) quote = "";
    } else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "{") depth++;
    else if (ch === "}") depth--;
  }
  return depth;
}

/**
 * A flow map that starts with `first` on raw line `start`, joined with the
 * raw lines that continue it, closing braces included. Reading stops at the
 * closing brace, or at the next entry at the map's own indentation; a map
 * that never closes is closed there, failing towards a report.
 */
function joinFlow(rawLines: string[], start: number, first: string, baseIndent: number): string {
  let text = first;
  let depth = braceDepth(first);
  for (let j = start + 1; depth > 0 && j < rawLines.length; j++) {
    const line = stripHashComment(rawLines[j]!);
    if (line.trim() === "") continue;
    const indent = line.length - line.trimStart().length;
    if (indent <= baseIndent) break;
    text += " " + line.trim();
    depth += braceDepth(line);
  }
  // Cut at the brace that closes the map (a trailing `,` or text is not part of it).
  let level = 0;
  let quote = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === quote) quote = "";
    } else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "{") level++;
    else if (ch === "}" && --level === 0) return text.slice(0, i + 1);
  }
  return text.replace(/[,\s]+$/, "") + "}".repeat(Math.max(level, 0));
}

/** Is this the pub.dev registry (or a known mirror), however the URL is spelled? */
function isPubHost(url: string): boolean {
  try {
    const u = new URL(url);
    const host = u.host.replace(/\.(?=:|$)/, "");
    return PUB_HOSTS.has(`https://${host}`) && (u.protocol === "https:" || u.protocol === "http:");
  } catch {
    return PUB_HOSTS.has(url.replace(/\/+$/, "").toLowerCase());
  }
}

/** A dependency's map (block or flow form) to a pub package, or nothing. */
function pubDependency(name: string, fields: Field[], line: number): PubPackage | undefined {
  // `git`/`path`/`sdk` have no pub identity; `hosted` must name pub.dev.
  if (fields.some((f) => f.key === "git" || f.key === "path" || f.key === "sdk")) return undefined;
  const hosted = fields.find((f) => f.key === "hosted");
  if (hosted) {
    // A hosted value that names no readable URL is taken as pub.dev, so a
    // malformed map fails towards a report.
    const text = `${hosted.value} ${fields.find((f) => f.key === "url")?.value ?? ""}`;
    const url = /https?:\/\/[^\s,}'"]+/.exec(text)?.[0];
    if (url !== undefined && !isPubHost(url)) return undefined;
  }
  const version = fields.find((f) => f.key === "version")?.value;
  return { name, version: version && EXACT_VERSION.test(version) ? version : undefined, line };
}

function extractPubspec(lines: Line[], rawLines: string[]): PubPackage[] {
  const out: PubPackage[] = [];
  lines.forEach((section, i) => {
    if (section.indent !== 0 || !DEPENDENCY_SECTIONS.has(section.key)) return;
    if (section.value.startsWith("{")) {
      // The whole section as one flow map: `dependencies: {name: 1.0.0}`.
      const flow = joinFlow(rawLines, section.line - 1, section.value, 0);
      for (const [name, value] of topLevelPairs(flow)) {
        if (!PUB_NAME.test(name)) continue;
        if (value.startsWith("{")) {
          const pkg = pubDependency(name, flowPairs(value), section.line);
          if (pkg) out.push(pkg);
        } else {
          out.push({ name, version: EXACT_VERSION.test(value) ? value : undefined, line: section.line });
        }
      }
      return;
    }
    const body = childrenOf(lines, i);
    const depIndent = body[0]?.indent;
    body.forEach((dep, k) => {
      if (dep.indent !== depIndent || !PUB_NAME.test(dep.key)) return;
      if (dep.value.startsWith("{")) {
        // Flow form: `name: {path: ../x}`, or the same map continued over the
        // following lines, read from the raw text so that a closing brace on
        // its own line counts (see joinFlow).
        const flow = joinFlow(rawLines, dep.line - 1, dep.value, dep.indent);
        const pkg = pubDependency(dep.key, flowPairs(flow), dep.line);
        if (pkg) out.push(pkg);
        return;
      }
      if (dep.value) {
        // Short form: `name: <constraint>`.
        out.push({ name: dep.key, version: EXACT_VERSION.test(dep.value) ? dep.value : undefined, line: dep.line });
        return;
      }
      // Long form: a map with `hosted`/`version`, or `git`/`path`/`sdk`.
      const fields: Line[] = [];
      for (let j = k + 1; j < body.length && body[j]!.indent > depIndent!; j++) fields.push(body[j]!);
      const pkg = pubDependency(dep.key, fields, dep.line);
      if (pkg) out.push(pkg);
    });
  });
  return out;
}

/**
 * Extract every pub.dev package a pubspec declares or locks.
 */
export function extractPubPackages(content: string, relativePath: string): PubPackage[] {
  const lines = readLines(content);
  const basename = relativePath.replace(/\\/g, "/").split("/").pop() ?? "";
  return basename === "pubspec.lock" ? extractLock(lines) : extractPubspec(lines, content.split(/\r?\n/));
}

/**
 * Scan a pubspec file for packages matching `pub:` feed IOCs.
 */
export function scanPubContent(content: string, relativePath: string, feed?: FeedIOC[]): Finding[] {
  const iocFeed = feed ?? loadThreatIntel();
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const p of extractPubPackages(content, relativePath)) {
    const key = `${p.name}@${p.version ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const ioc = matchPackageIOC("pub", p.name, p.version, iocFeed);
    if (!ioc) continue;
    findings.push({
      rule: "PUB_MALICIOUS_PACKAGE",
      description: `Known malicious pub package: ${p.name}${p.version ? `@${p.version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
      severity: ioc.severity,
      file: relativePath,
      line: p.line,
      match: p.version ? `${p.name}@${p.version}` : p.name,
      confidence: ioc.confidence,
      category: "malware",
      recommendation: `Upgrade or remove ${p.name}, clear it from the pub cache (dart pub cache clean or ~/.pub-cache), `
        + "and rotate credentials available to machines that built it. This package version is listed in threat intelligence feeds.",
    });
  }
  return findings;
}
