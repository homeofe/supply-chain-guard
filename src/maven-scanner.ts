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
 *     resolved from the pom's own `<properties>` (top level, then profiles);
 *     anything else stays unknown.
 *   - `gradle.lockfile`: `group:artifact:version=configurations`, exact.
 *   - `*.gradle` / `*.gradle.kts`: quoted `group:artifact:version` strings, and
 *     `conf "group:artifact"` with a variable or no version (unknown).
 *   - `gradle/libs.versions.toml`: the `[libraries]` and `[plugins]` tables of
 *     a version catalog, including rich versions (`{ strictly = "v" }`).
 *   - Gradle named arguments (`group: 'g', name: 'a', version: 'v'` and the
 *     Kotlin `group = "g", name = "a", version = "v"` form).
 *   - Gradle `plugins { id("x") version "v" }` and `kotlin("x") version "v"`,
 *     as the plugin marker artifact `x:x.gradle.plugin` the id resolves through.
 *   - SBT (`*.sbt`): `"g" % "a" % v`, and `"g" %% "a" % v` / `%%%` (Scala.js),
 *     whose artifact carries the Scala binary version the file does not state,
 *     so each binary version (2.11, 2.12, 2.13, 3) is a candidate.
 *   - Bazel `maven_install.json` (rules_jvm_external), both lockfile formats.
 *
 * An unresolved version is passed as unknown, so only a whole-artifact entry
 * can fire on it; a version pin needs the exact version, which the lockfile
 * and literal declarations provide.
 */

import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { stripHashComment, lineAtOffset } from "./text-lines.js";

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
  if (basename === "pom.xml" || basename === "gradle.lockfile" || basename === "maven_install.json") return true;
  if (basename.endsWith(".sbt")) return true;
  if (basename.endsWith(".gradle") || basename.endsWith(".gradle.kts")) return true;
  return basename.endsWith(".versions.toml") && parts[parts.length - 2] === "gradle";
}


/** Blank out a region, keeping newlines so offsets and line numbers survive. */
function blank(text: string): string {
  return text.replace(/[^\n]/g, " ");
}

function extractPom(content: string): MavenCoordinate[] {
  const source = content.replace(/<!--[\s\S]*?-->/g, blank);

  // Model properties live in the project's <properties> and in each
  // profile's; a <properties> under a plugin <configuration> is plugin input,
  // not a model property. The top level wins over a profile. Versions are
  // resolved after the walk, since properties may follow the dependencies.
  const topProperties = new Map<string, string>();
  const profileProperties = new Map<string, string>();
  const resolve = (value: string | undefined): string | undefined => {
    if (value === undefined) return undefined;
    const v = value.trim().replace(/\$\{([^}]+)\}/g, (_, key: string) =>
      topProperties.get(key) ?? profileProperties.get(key) ?? "\u0000");
    return new RegExp(`^${VERSION}$`).test(v) ? v : undefined;
  };

  interface Frame { name: string; offset: number; fields: Record<string, string> }
  const stack: Frame[] = [];
  const pending: { group: string; artifact: string; version: string | undefined; line: number }[] = [];
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
    if (parent?.name === "properties") {
      const owner = stack[stack.length - 2]?.name;
      const scope = owner === "project" ? topProperties : owner === "profile" ? profileProperties : undefined;
      if (scope && !scope.has(name!)) scope.set(name!, text.trim());
      continue;
    }
    // Recorded on the DIRECT parent only, so an <exclusion>'s or a
    // <configuration>'s groupId never lands on the enclosing dependency.
    if ((name === "groupId" || name === "artifactId" || name === "version") && parent) {
      parent.fields[name] = text.trim();
    } else if (COORDINATE_ELEMENTS.has(name!)) {
      const group = frame.fields.groupId ?? (name === "plugin" ? DEFAULT_PLUGIN_GROUP : undefined);
      const artifact = frame.fields.artifactId;
      if (group && artifact && new RegExp(`^${ID}$`).test(group) && new RegExp(`^${ID}$`).test(artifact)) {
        pending.push({ group, artifact, version: frame.fields.version, line: lineAtOffset(source, frame.offset) });
      }
    }
  }
  return pending.map((c) => ({ ...c, version: resolve(c.version) }));
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
    // Same artifact with a variable, catalog accessor or no version at all
    // (platform/BOM-managed): the version is unknown, the artifact is not.
    for (const m of line.matchAll(DECLARATION)) {
      const [, configuration, , group, artifact, rest] = m;
      if (!isGradleConfiguration(configuration!)) continue;
      if (rest !== undefined && LITERAL_TAIL.test(rest)) continue; // read above, with its version
      out.push({ group: group!, artifact: artifact!, version: undefined, line: i + 1 });
    }
    const named = namedCoordinate(line);
    if (named) out.push({ ...named, line: i + 1 });
    const plugin = PLUGIN_ID.exec(line);
    if (plugin) {
      out.push({ group: plugin[1]!, artifact: `${plugin[1]}.gradle.plugin`, version: plugin[2], line: i + 1 });
    }
    // kotlin("x") in plugins {} is the id org.jetbrains.kotlin.x; without a
    // version it is the dependency shorthand instead, so a version is required.
    const kotlin = KOTLIN_PLUGIN.exec(line);
    if (kotlin) {
      const id = `org.jetbrains.kotlin.${kotlin[1]}`;
      out.push({ group: id, artifact: `${id}.gradle.plugin`, version: kotlin[2], line: i + 1 });
    }
  });
  return out;
}

// Spacing is [ \t]* with no two runs adjacent: `\s*\(?\s*` is quadratic on a
// long whitespace run, since both runs can split it every way.
const PLUGIN_ID = new RegExp(
  `\\bid[ \\t]*(?:\\([ \\t]*)?['"](${ID})['"](?:[ \\t]*\\))?[ \\t]+version[ \\t]*(?:\\([ \\t]*)?['"](${VERSION})['"]`);
const KOTLIN_PLUGIN = new RegExp(
  `\\bkotlin[ \\t]*\\([ \\t]*"([a-z][A-Za-z0-9_.-]*)"[ \\t]*\\)[ \\t]+version[ \\t]*(?:\\([ \\t]*)?"(${VERSION})"`);

/** `conf "g:a[:rest]"`, `conf("g:a[:rest]")`, optionally wrapped in platform(...). */
const DECLARATION = new RegExp(
  `\\b([A-Za-z_][A-Za-z0-9_]*)[ \\t]*(?:\\([ \\t]*)?(?:(?:platform|enforcedPlatform|testFixtures)[ \\t]*\\([ \\t]*)?`
  + `(['"])(${ID}):(${ID})(?::([^'"\\s]*))?\\2`, "g");
/** A literal version tail, as the coordinate-string regex reads it. */
const LITERAL_TAIL = new RegExp(`^${VERSION}(?::[A-Za-z0-9_.-]+)?(?:@[A-Za-z0-9]+)?$`);

const GRADLE_CONFIGURATIONS = new Set([
  "implementation", "api", "compile", "compileOnly", "compileOnlyApi", "runtime", "runtimeOnly",
  "annotationProcessor", "kapt", "ksp", "classpath", "developmentOnly", "detektPlugins", "lintChecks",
  "coreLibraryDesugaring",
]);
const GRADLE_CONFIGURATION_SUFFIXES = ["Implementation", "Api", "CompileOnly", "RuntimeOnly", "AnnotationProcessor"];

/**
 * A dependency configuration: a version-less `"g:a"` elsewhere (a
 * substitution target, an exclude, a log line) is not something the build
 * resolves, so only a known configuration or a source-set variant counts.
 */
function isGradleConfiguration(name: string): boolean {
  return GRADLE_CONFIGURATIONS.has(name) || GRADLE_CONFIGURATION_SUFFIXES.some((s) => name.length > s.length && name.endsWith(s));
}

/** `group: 'g', name: 'a', version: 'v'` (Groovy) or `group = "g", name = "a", version = "v"` (Kotlin). */
function namedCoordinate(line: string): Omit<MavenCoordinate, "line"> | null {
  const field = (key: string) =>
    new RegExp(`\\b${key}\\s*[:=]\\s*['"]([^'"]+)['"]`).exec(line)?.[1];
  const group = field("group");
  const artifact = field("name");
  if (!group || !artifact) return null;
  const idRe = new RegExp(`^${ID}$`);
  if (!idRe.test(group) || !idRe.test(artifact)) return null;
  const version = field("version");
  return { group, artifact, version: version && new RegExp(`^${VERSION}$`).test(version) ? version : undefined };
}

/** Scala binary versions an SBT `%%` / `%%%` dependency may resolve to. */
const SCALA_BINARY_VERSIONS = ["2.11", "2.12", "2.13", "3"];

function extractSbt(content: string): MavenCoordinate[] {
  const out: MavenCoordinate[] = [];
  // The version is a string literal or a val (`% libVersion`, `% V.lib`),
  // which stays unknown.
  const re = new RegExp(`"(${ID})"[ \\t]*(%{1,3})[ \\t]*"(${ID})"[ \\t]*%[ \\t]*(?:"(${VERSION})"|[A-Za-z_][A-Za-z0-9_.]*)`, "g");
  content.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.replace(/\/\/.*$/, "");
    for (const m of line.matchAll(re)) {
      const [, group, op, artifact, version] = m;
      // %% resolves only the _<scala binary> artifact and %%% the Scala.js
      // one; the plain name is a different artifact the build never fetches.
      const artifacts = op === "%" ? [artifact!]
        : SCALA_BINARY_VERSIONS.map((v) => `${artifact}_${op === "%%%" ? "sjs1_" : ""}${v}`);
      for (const a of artifacts) out.push({ group: group!, artifact: a, version, line: i + 1 });
    }
  });
  return out;
}

/** Bazel rules_jvm_external lockfile: v2 `artifacts` map, or v1 `dependency_tree`. */
function extractMavenInstall(content: string): MavenCoordinate[] {
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== "object") return [];
  const out: MavenCoordinate[] = [];
  const idRe = new RegExp(`^${ID}$`);
  const verRe = new RegExp(`^${VERSION}$`);
  // v1 lists one entry per classifier (jar, sources, javadoc) of the same artifact.
  const seen = new Set<string>();
  const push = (group: string | undefined, artifact: string | undefined, version: string | undefined) => {
    if (!group || !artifact || !idRe.test(group) || !idRe.test(artifact)) return;
    const v = version && verRe.test(version) ? version : undefined;
    const key = `${group}:${artifact}@${v ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ group, artifact, version: v, line: 1 });
  };
  const artifacts = (doc as { artifacts?: unknown }).artifacts;
  if (artifacts && typeof artifacts === "object") {
    for (const [key, value] of Object.entries(artifacts as Record<string, unknown>)) {
      const [group, artifact] = key.split(":");
      const version = (value as { version?: unknown })?.version;
      push(group, artifact, typeof version === "string" ? version : undefined);
    }
  }
  const deps = (doc as { dependency_tree?: { dependencies?: unknown } }).dependency_tree?.dependencies;
  if (Array.isArray(deps)) {
    for (const dep of deps) {
      const coord = (dep as { coord?: unknown })?.coord;
      if (typeof coord !== "string") continue;
      // group:artifact[:packaging[:classifier]]:version
      const parts = coord.split(":");
      if (parts.length >= 3) push(parts[0], parts[1], parts[parts.length - 1]);
    }
  }
  return out;
}

function extractVersionCatalog(content: string): MavenCoordinate[] {
  const out: MavenCoordinate[] = [];
  const versions = new Map<string, string>();
  const libraries: { key: string; value: string; line: number }[] = [];
  const plugins: { value: string; line: number }[] = [];
  let section = "";

  const str = (body: string, key: string): string | undefined =>
    new RegExp(`(?:^|[{,\\s])${key.replace(/\./g, "\\.")}\\s*=\\s*"([^"]*)"`).exec(body)?.[1];
  // A rich version `{ strictly = "x" }` (or require / prefer): strictly is
  // what resolves; prefer is chosen over a require lower bound.
  const rich = (body: string): string | undefined =>
    str(body, "strictly") ?? str(body, "prefer") ?? str(body, "require");
  /** `version = "x"`, `version.ref = "k"` or `version = { strictly = "x" }` inside a table body. */
  const versionOf = (body: string): string | undefined => {
    const ref = str(body, "version.ref");
    if (ref !== undefined) return versions.get(ref);
    const plain = str(body, "version");
    if (plain !== undefined) return plain;
    const open = /(?:^|[{,\s])version\s*=\s*\{/.exec(body);
    return open ? rich(body.slice(open.index)) : undefined;
  };

  content.split(/\r?\n/).forEach((raw, i) => {
    const line = stripHashComment(raw).trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1]!.trim();
      return;
    }
    const kv = /^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) return;
    const value = kv[2]!.trim();
    if (section === "versions") {
      const v = /^"([^"]*)"$/.exec(value)?.[1] ?? (value.startsWith("{") ? rich(value) : undefined);
      if (v !== undefined) versions.set(kv[1]!, v);
    } else if (section === "libraries") {
      libraries.push({ key: kv[1]!, value, line: i + 1 });
    } else if (section === "plugins") {
      plugins.push({ value, line: i + 1 });
    }
  });

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
      version = versionOf(lib.value);
    }
    if (group && artifact && idRe.test(group) && idRe.test(artifact)) {
      out.push({ group, artifact, version: version && verRe.test(version) ? version : undefined, line: lib.line });
    }
  }

  // [plugins]: a plugin id resolves through its marker artifact id:id.gradle.plugin.
  for (const plugin of plugins) {
    let id: string | undefined;
    let version: string | undefined;
    const plain = new RegExp(`^"(${ID})(?::(${VERSION}))?"$`).exec(plugin.value);
    if (plain) {
      [, id, version] = plain;
    } else if (plugin.value.startsWith("{")) {
      id = str(plugin.value, "id");
      version = versionOf(plugin.value);
    }
    if (id && idRe.test(id)) {
      out.push({ group: id, artifact: `${id}.gradle.plugin`, version: version && verRe.test(version) ? version : undefined, line: plugin.line });
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
  if (basename === "maven_install.json") return extractMavenInstall(content);
  if (basename.endsWith(".sbt")) return extractSbt(content);
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
