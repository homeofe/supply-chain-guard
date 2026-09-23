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

export interface PubPackage {
  name: string;
  version: string | undefined;
  line: number;
}

const PUB_HOSTS = new Set(["https://pub.dev", "https://pub.dartlang.org"]);
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
    const text = raw.replace(/\s+#.*$/, "");
    if (!text.trim() || text.trim().startsWith("#")) return;
    const m = /^(\s*)([^:\s][^:]*?)\s*:\s*(.*)$/.exec(text);
    if (!m) return;
    out.push({ indent: m[1]!.length, key: m[2]!.trim(), value: unquote(m[3]!.trim()), line: i + 1 });
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
    if (!url || !PUB_HOSTS.has(url.replace(/\/+$/, ""))) continue;
    if (!PUB_NAME.test(name)) continue;
    out.push({ name, version: version && EXACT_VERSION.test(version) ? version : undefined, line: entry.line });
  }
  return out;
}

function extractPubspec(lines: Line[]): PubPackage[] {
  const out: PubPackage[] = [];
  lines.forEach((section, i) => {
    if (section.indent !== 0 || !DEPENDENCY_SECTIONS.has(section.key)) return;
    const body = childrenOf(lines, i);
    const depIndent = body[0]?.indent;
    body.forEach((dep, k) => {
      if (dep.indent !== depIndent || !PUB_NAME.test(dep.key)) return;
      if (dep.value) {
        // Short form: `name: <constraint>`.
        out.push({ name: dep.key, version: EXACT_VERSION.test(dep.value) ? dep.value : undefined, line: dep.line });
        return;
      }
      // Long form: a map with `hosted`/`version`, or `git`/`path`/`sdk`.
      const fields: Line[] = [];
      for (let j = k + 1; j < body.length && body[j]!.indent > depIndent!; j++) fields.push(body[j]!);
      if (fields.some((f) => f.key === "git" || f.key === "path" || f.key === "sdk")) return;
      const hosted = fields.find((f) => f.key === "hosted");
      const hostedUrl = hosted?.value || fields.find((f) => f.key === "url")?.value;
      if (hosted && hostedUrl && !PUB_HOSTS.has(hostedUrl.replace(/\/+$/, ""))) return;
      const version = fields.find((f) => f.key === "version")?.value;
      out.push({ name: dep.key, version: version && EXACT_VERSION.test(version) ? version : undefined, line: dep.line });
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
  return basename === "pubspec.lock" ? extractLock(lines) : extractPubspec(lines);
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
