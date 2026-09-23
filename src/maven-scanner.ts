/**
 * Maven / Gradle dependency scanner.
 *
 * Resolves the Maven coordinates a JVM build pulls in and matches them against
 * `maven:<groupId>:<artifactId>[@version]` feed entries. Coordinates are
 * case-sensitive, as they are on Maven Central, so nothing is folded.
 *
 * Sources:
 *   - `pom.xml`: `<dependency>`, `<plugin>`, `<extension>` and `<parent>`.
 *     Plugins and extensions execute during the build, so they are
 *     dependencies in the sense that matters here. A `${property}` version is
 *     resolved from the pom's own `<properties>`; anything else stays unknown.
 *   - `gradle.lockfile`: `group:artifact:version=configurations`, exact.
 *   - `*.gradle` / `*.gradle.kts`: quoted `group:artifact:version` strings.
 *   - `gradle/libs.versions.toml`: the `[libraries]` table of a version catalog.
 *
 * An unresolved version is passed as unknown, so only a whole-artifact entry
 * can fire on it; a version pin needs the exact version, which the lockfile
 * and literal declarations provide.
 */

import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";

export interface MavenCoordinate {
  group: string;
  artifact: string;
  version: string | undefined;
  line: number;
}

/** groupId / artifactId: a letter first, then the Maven identifier charset. */
const ID = "[A-Za-z][A-Za-z0-9_.-]*";
const VERSION = "[A-Za-z0-9][A-Za-z0-9_.+-]*";

/** Elements whose direct groupId/artifactId/version children name an artifact. */
const COORDINATE_ELEMENTS = new Set(["dependency", "plugin", "extension", "parent"]);

/** Maven's documented default groupId for a plugin that omits it. */
const DEFAULT_PLUGIN_GROUP = "org.apache.maven.plugins";

/**
 * Check if a file declares or locks Maven artifacts.
 */
export function isMavenFile(relativePath: string): boolean {
  const parts = relativePath.replace(/\\/g, "/").split("/");
  const basename = parts[parts.length - 1] ?? "";
  if (basename === "pom.xml" || basename === "gradle.lockfile") return true;
  if (basename.endsWith(".gradle") || basename.endsWith(".gradle.kts")) return true;
  return basename.endsWith(".versions.toml") && parts[parts.length - 2] === "gradle";
}

function lineAt(content: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

/** Blank out a region, keeping newlines so offsets and line numbers survive. */
function blank(text: string): string {
  return text.replace(/[^\n]/g, " ");
}

function extractPom(content: string): MavenCoordinate[] {
  const source = content.replace(/<!--[\s\S]*?-->/g, blank);

  const properties = new Map<string, string>();
  const propsBlock = /<properties>([\s\S]*?)<\/properties>/.exec(source);
  if (propsBlock) {
    for (const m of (propsBlock[1] ?? "").matchAll(/<([A-Za-z][\w.-]*)>\s*([^<]*?)\s*<\/\1>/g)) {
      properties.set(m[1]!, m[2]!);
    }
  }
  const resolve = (value: string | undefined): string | undefined => {
    if (value === undefined) return undefined;
    const v = value.trim().replace(/\$\{([^}]+)\}/g, (_, key: string) => properties.get(key) ?? "\u0000");
    return new RegExp(`^${VERSION}$`).test(v) ? v : undefined;
  };

  interface Frame { name: string; offset: number; fields: Record<string, string> }
  const stack: Frame[] = [];
  const out: MavenCoordinate[] = [];
  const tag = /<(\/?)([A-Za-z][\w.:-]*)\b[^>]*?(\/?)>/g;
  let textStart = 0;
  for (let m = tag.exec(source); m; m = tag.exec(source)) {
    const [, closing, name, selfClosing] = m;
    const text = source.slice(textStart, m.index);
    textStart = tag.lastIndex;
    if (selfClosing) continue;
    if (!closing) {
      stack.push({ name: name!, offset: m.index, fields: {} });
      continue;
    }
    // Pop to the matching open element; tolerate unbalanced input.
    let idx = stack.length - 1;
    while (idx >= 0 && stack[idx]!.name !== name) idx--;
    if (idx < 0) continue;
    const frame = stack[idx]!;
    stack.length = idx;
    const parent = stack[stack.length - 1];
    // Recorded on the DIRECT parent only, so an <exclusion>'s or a
    // <configuration>'s groupId never lands on the enclosing dependency.
    if ((name === "groupId" || name === "artifactId" || name === "version") && parent) {
      parent.fields[name] = text.trim();
    } else if (COORDINATE_ELEMENTS.has(name!)) {
      const group = frame.fields.groupId ?? (name === "plugin" ? DEFAULT_PLUGIN_GROUP : undefined);
      const artifact = frame.fields.artifactId;
      if (group && artifact && new RegExp(`^${ID}$`).test(group) && new RegExp(`^${ID}$`).test(artifact)) {
        out.push({ group, artifact, version: resolve(frame.fields.version), line: lineAt(source, frame.offset) });
      }
    }
  }
  return out;
}

function extractGradleLockfile(content: string): MavenCoordinate[] {
  const out: MavenCoordinate[] = [];
  const re = new RegExp(`^(${ID}):(${ID}):(${VERSION})=`);
  content.split(/\r?\n/).forEach((line, i) => {
    const m = re.exec(line.trim());
    if (m) out.push({ group: m[1]!, artifact: m[2]!, version: m[3], line: i + 1 });
  });
  return out;
}

function extractGradleScript(content: string): MavenCoordinate[] {
  const out: MavenCoordinate[] = [];
  // Whole quoted string only: group:artifact:version, optional :classifier and @ext.
  const re = new RegExp(`(['"])(${ID}):(${ID}):(${VERSION})(?::[A-Za-z0-9_.-]+)?(?:@[A-Za-z0-9]+)?\\1`, "g");
  let inBlockComment = false;
  content.split(/\r?\n/).forEach((raw, i) => {
    let line = raw;
    if (inBlockComment) {
      const end = line.indexOf("*/");
      if (end < 0) return;
      line = line.slice(end + 2);
      inBlockComment = false;
    }
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
    if (trimmed.startsWith("/*")) {
      if (!trimmed.includes("*/")) inBlockComment = true;
      return;
    }
    for (const m of line.matchAll(re)) {
      out.push({ group: m[2]!, artifact: m[3]!, version: m[4], line: i + 1 });
    }
  });
  return out;
}

function extractVersionCatalog(content: string): MavenCoordinate[] {
  const out: MavenCoordinate[] = [];
  const versions = new Map<string, string>();
  const libraries: { key: string; value: string; line: number }[] = [];
  let section = "";
  content.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, "").trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1]!.trim();
      return;
    }
    const kv = /^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) return;
    if (section === "versions") {
      const v = /^"([^"]*)"$/.exec(kv[2]!.trim());
      if (v) versions.set(kv[1]!, v[1]!);
    } else if (section === "libraries") {
      libraries.push({ key: kv[1]!, value: kv[2]!.trim(), line: i + 1 });
    }
  });

  const str = (body: string, key: string): string | undefined =>
    new RegExp(`(?:^|[{,\\s])${key.replace(/\./g, "\\.")}\\s*=\\s*"([^"]*)"`).exec(body)?.[1];
  const idRe = new RegExp(`^${ID}$`);
  const verRe = new RegExp(`^${VERSION}$`);

  for (const lib of libraries) {
    let group: string | undefined;
    let artifact: string | undefined;
    let version: string | undefined;
    const plain = new RegExp(`^"(${ID}):(${ID})(?::(${VERSION}))?"$`).exec(lib.value);
    if (plain) {
      [, group, artifact, version] = plain;
    } else if (lib.value.startsWith("{")) {
      const module = str(lib.value, "module");
      if (module) [group, artifact] = module.split(":");
      else {
        group = str(lib.value, "group");
        artifact = str(lib.value, "name");
      }
      const ref = str(lib.value, "version.ref");
      version = ref !== undefined ? versions.get(ref) : str(lib.value, "version");
    }
    if (group && artifact && idRe.test(group) && idRe.test(artifact)) {
      out.push({ group, artifact, version: version && verRe.test(version) ? version : undefined, line: lib.line });
    }
  }
  return out;
}

/**
 * Extract every Maven coordinate a build file declares or locks.
 */
export function extractMavenCoordinates(content: string, relativePath: string): MavenCoordinate[] {
  const basename = relativePath.replace(/\\/g, "/").split("/").pop() ?? "";
  if (basename === "pom.xml") return extractPom(content);
  if (basename === "gradle.lockfile") return extractGradleLockfile(content);
  if (basename.endsWith(".versions.toml")) return extractVersionCatalog(content);
  if (basename.endsWith(".gradle") || basename.endsWith(".gradle.kts")) return extractGradleScript(content);
  return [];
}

/**
 * Scan a Maven or Gradle file for artifacts matching `maven:` feed IOCs.
 */
export function scanMavenContent(content: string, relativePath: string, feed?: FeedIOC[]): Finding[] {
  const iocFeed = feed ?? loadThreatIntel();
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const c of extractMavenCoordinates(content, relativePath)) {
    const id = `${c.group}:${c.artifact}`;
    const key = `${id}@${c.version ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const ioc = matchPackageIOC("maven", id, c.version, iocFeed);
    if (!ioc) continue;
    findings.push({
      rule: "MAVEN_MALICIOUS_PACKAGE",
      description: `Known malicious Maven artifact: ${id}${c.version ? `@${c.version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
      severity: ioc.severity,
      file: relativePath,
      line: c.line,
      match: c.version ? `${id}@${c.version}` : id,
      confidence: ioc.confidence,
      category: "malware",
      recommendation: `Remove ${id} from the build, purge it from the local repository (~/.m2, ~/.gradle/caches), `
        + "and rotate credentials available to the builds that resolved it. This artifact is listed in threat intelligence feeds.",
    });
  }
  return findings;
}
