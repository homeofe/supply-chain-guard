/**
 * Manifest matchers for ecosystems that share one dispatch path.
 *
 * Each entry says which files it reads, how it extracts package identities,
 * which feed prefix those identities live under and which rule reports a
 * match. scanner.ts dispatches every file one of these recognises, at any
 * depth, through scanRegistryFile(): one dispatch point per file.
 *
 * Identity rules that keep false positives out:
 *   - A version is passed only when the file states an exact one; a range or
 *     constraint leaves it unknown, so only a whole-name entry can match.
 *   - Registry-specific identities stay separate: a Chrome and an Edge store
 *     ID are different extensions, a chart from one repository is not the
 *     same-named chart from another.
 *   - Local, path, git and private-host sources name nothing in a public
 *     registry and are skipped.
 */

import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { stripHashComment, lineOfNeedle, lineAtOffset } from "./text-lines.js";

export interface PackageRef {
  name: string;
  version: string | undefined;
  line: number;
  /** Feed prefixes to try, in order; defaults to the matcher's own. */
  ecosystems?: string[];
}

export interface EcosystemMatcher {
  /** Feed prefix without the colon. */
  id: string;
  label: string;
  rule: string;
  /** Files read, for documentation and the coverage table. */
  reads: string;
  isFile(relativePath: string): boolean;
  extract(content: string, relativePath: string): PackageRef[];
  remediation: string;
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

const EXACT_SEMVER = /^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.+-]+)?$/;

function exactVersion(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const v = raw.trim().replace(/^==\s*/, "");
  return EXACT_SEMVER.test(v) ? v : undefined;
}

function pathParts(relativePath: string): string[] {
  return relativePath.replace(/\\/g, "/").split("/");
}

function basenameOf(relativePath: string): string {
  const parts = pathParts(relativePath);
  return parts[parts.length - 1] ?? "";
}

function parseJson(content: string): unknown {
  try {
    return JSON.parse(content.replace(/^\uFEFF/, ""));
  } catch {
    return undefined;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function unquote(value: string): string {
  const m = /^\s*(["'])(.*)\1\s*$/.exec(value);
  return m ? m[2]! : value.trim();
}

/**
 * Line lookup for identities that appear in document order (JSON lockfiles).
 * Searching each needle from offset 0 is quadratic over thousands of entries,
 * so the search resumes where the previous hit ended. Misses (out-of-order or
 * absent needles) get a small budget of full-text searches; once it is spent
 * every lookup answers line 1, so a hostile file whose needles never occur
 * cannot make every lookup scan the whole text.
 */
function orderedLocator(content: string): (needle: string) => number {
  let cursor = 0;
  let misses = 16;
  return (needle) => {
    if (misses <= 0) return 1;
    let idx = content.indexOf(needle, cursor);
    if (idx < 0) {
      misses--;
      idx = content.indexOf(needle);
    }
    if (idx < 0) return 1;
    cursor = idx + needle.length;
    return lineAtOffset(content, idx);
  };
}

/** Text with every complete XML comment removed, in linear time. */
function stripXmlComments(text: string): string {
  let out = "";
  let pos = 0;
  for (let open = text.indexOf("<!--"); open >= 0; open = text.indexOf("<!--", pos)) {
    const close = text.indexOf("-->", open + 4);
    // An unclosed comment is left in place, as the regex this replaces did:
    // dropping the rest of the file would let one "<!--" hide an id.
    if (close < 0) break;
    out += text.slice(pos, open);
    pos = close + 3;
  }
  return out + text.slice(pos);
}


/**
 * Git-hosted package identity as OSV's SwiftURL ecosystem spells it:
 * host/owner/repo, no scheme, no .git, lowercase. Returns null for anything
 * that is not a remote repository URL.
 */
export function normalizeRepositoryUrl(raw: string): string | null {
  let url = raw.trim();
  const scp = /^[\w.-]+@([\w.-]+):(.+)$/.exec(url);
  if (scp) url = `${scp[1]}/${scp[2]}`;
  url = url.replace(/^(?:https?|git|ssh):\/\//i, "").replace(/^[^@/]+@/, "");
  url = url.replace(/\.git$/i, "").replace(/\/+$/, "");
  const parts = url.split("/");
  // A real host name: dot-separated labels, no leading dot ("../x" is a path).
  if (parts.length < 3 || !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(parts[0]!)) return null;
  if (!parts.every((p) => /^[A-Za-z0-9._-]+$/.test(p))) return null;
  return parts.join("/").toLowerCase();
}

// ---------------------------------------------------------------------------
// Swift Package Manager
// ---------------------------------------------------------------------------

const swift: EcosystemMatcher = {
  id: "swift",
  label: "Swift Package Manager",
  rule: "SWIFT_MALICIOUS_PACKAGE",
  reads: "Package.resolved, Package.swift",
  isFile: (p) => ["Package.resolved", "Package.swift"].includes(basenameOf(p)),
  extract(content, p) {
    const out: PackageRef[] = [];
    if (basenameOf(p) === "Package.resolved") {
      const doc = parseJson(content);
      if (!isObject(doc)) return out;
      const pins = Array.isArray(doc.pins) ? doc.pins
        : isObject(doc.object) && Array.isArray(doc.object.pins) ? doc.object.pins : [];
      const lineOf = orderedLocator(content);
      for (const pin of pins) {
        if (!isObject(pin)) continue;
        // Local pins carry a path, which normalizeRepositoryUrl rejects.
        const url = typeof pin.location === "string" ? pin.location
          : typeof pin.repositoryURL === "string" ? pin.repositoryURL : undefined;
        const name = url ? normalizeRepositoryUrl(url) : null;
        const state = isObject(pin.state) ? pin.state : {};
        if (name) out.push({ name, version: exactVersion(typeof state.version === "string" ? state.version : undefined), line: lineOf(url!) });
      }
      return out;
    }
    // Whole-line comments only: a "//" inside "https://" is not a comment.
    // Blanking them keeps line numbers, and the arguments of one .package(
    // may span lines (swift-format puts each on its own line).
    const text = content.split("\n").map((raw) => (raw.trim().startsWith("//") ? "" : raw)).join("\n");
    // Offsets just past each "(" of a ".package(" call.
    const starts = Array.from(text.matchAll(/\.package\s*\(/g), (c) => c.index + c[0].length);
    starts.forEach((start, k) => {
      // The call ends at its matching ")", and never past the next .package(,
      // so an unclosed call cannot make every later one rescan the file.
      const limit = starts[k + 1] ?? text.length;
      let depth = 1;
      let end = limit;
      for (let j = start; j < limit; j++) {
        const c = text.charCodeAt(j);
        if (c === 0x28) depth++;
        else if (c === 0x29 && --depth === 0) { end = j; break; }
      }
      const args = text.slice(start, end);
      const url = /(?:^|[\s,(])(url\s*:\s*"([^"]+)")/.exec(args);
      const name = url ? normalizeRepositoryUrl(url[2]!) : null;
      if (!name) return;
      const exact = /(?:exact\s*:\s*|\.exact\s*\(\s*)"([^"]+)"/.exec(args);
      const offset = start + url!.index + url![0].length - url![1]!.length;
      out.push({ name, version: exactVersion(exact?.[1]), line: lineAtOffset(text, offset) });
    });
    return out;
  },
  remediation: "Remove the package from Package.swift, delete it from Package.resolved and the SwiftPM cache (~/Library/Caches/org.swift.swiftpm)",
};

// ---------------------------------------------------------------------------
// CocoaPods
// ---------------------------------------------------------------------------

/** Root pod of an entry ("Firebase/Core" is the Firebase pod), lowercase. */
function podRoot(raw: string): string {
  return unquote(raw).split("/")[0]!.trim().toLowerCase();
}

const cocoapods: EcosystemMatcher = {
  id: "cocoapods",
  label: "CocoaPods",
  rule: "COCOAPODS_MALICIOUS_POD",
  reads: "Podfile.lock, Podfile",
  isFile: (p) => ["Podfile", "Podfile.lock"].includes(basenameOf(p)),
  extract(content, p) {
    const out: PackageRef[] = [];
    const lines = content.split(/\r?\n/);
    if (basenameOf(p) === "Podfile.lock") {
      // Pods fetched from a path, git or podspec (EXTERNAL SOURCES) or from a
      // private spec repo (a non-trunk SPEC REPOS key) are not the trunk pod
      // of that name, the same boundary the Podfile path draws for :path.
      const external = new Set<string>();
      let section = "";
      let trunkRepo = false;
      for (const raw of lines) {
        if (/^\S/.test(raw)) { section = raw.trim(); continue; }
        const key = /^ {2}(\S.*?):\s*$/.exec(raw);
        if (section === "EXTERNAL SOURCES:" && key) external.add(podRoot(key[1]!));
        if (section !== "SPEC REPOS:") continue;
        // "trunk" (CocoaPods >= 1.7) or the master specs repo URL (older).
        if (key) trunkRepo = /^(?:trunk|https:\/\/(?:github\.com\/cocoapods\/specs(?:\.git)?|cdn\.cocoapods\.org)\/?)$/i.test(unquote(key[1]!));
        const item = /^ {4}- (.+)$/.exec(raw);
        if (item && !trunkRepo) external.add(podRoot(item[1]!));
      }
      let inPods = false;
      lines.forEach((raw, i) => {
        if (/^\S/.test(raw)) inPods = raw.trim() === "PODS:";
        if (!inPods) return;
        // Top-level entries are exact ("  - Name/Sub (1.2.3)"); nested
        // dependency lines carry constraints and are one level deeper.
        // CocoaPods quotes the whole entry when it needs to:
        // '  - "name (1.0.0)":'.
        const entry = /^ {2}- (.+)$/.exec(raw);
        if (!entry) return;
        let body = entry[1]!.trimEnd();
        if (body.endsWith(":")) body = body.slice(0, -1);
        const m = /^([^\s"'(]+) \(([^)]+)\)$/.exec(unquote(body));
        if (!m) return;
        const name = podRoot(m[1]!);
        if (!external.has(name)) out.push({ name, version: exactVersion(m[2]), line: i + 1 });
      });
      return out;
    }
    lines.forEach((raw, i) => {
      const line = raw.replace(/#.*$/, "");
      const m = /^\s*pod\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/.exec(line);
      if (m && !/:(?:git|path|podspec)\s*=>/.test(line) && !/\b(?:git|path|podspec):/.test(line)) {
        out.push({ name: m[1]!.split("/")[0]!.toLowerCase(), version: exactVersion(m[2]), line: i + 1 });
      }
    });
    return out;
  },
  remediation: "Remove the pod from the Podfile, run pod install, and clear it from the CocoaPods cache (pod cache clean)",
};

// ---------------------------------------------------------------------------
// Hex (Elixir / Erlang)
// ---------------------------------------------------------------------------

/**
 * {:atom, "requirement", opts} tuples on one line. The options run to the
 * tuple's "}" but never past the next "{", so a line of unclosed tuples is
 * read in linear time rather than rescanned from every "{".
 */
function hexTuples(line: string): Array<{ atom: string; requirement: string; rest: string }> {
  const out: Array<{ atom: string; requirement: string; rest: string }> = [];
  let close = -1;
  for (const m of line.matchAll(/\{\s*:([a-z0-9_]+)\s*,\s*"([^"]+)"/g)) {
    const from = m.index + m[0].length;
    // One "}" far ahead serves every tuple before it: search again only
    // once it is behind us.
    if (close < from) close = line.indexOf("}", from);
    if (close < 0) break;
    const open = line.indexOf("{", from);
    if (open >= 0 && open < close) continue;
    out.push({ atom: m[1]!, requirement: m[2]!, rest: line.slice(from, close) });
  }
  return out;
}

const hex: EcosystemMatcher = {
  id: "hex",
  label: "Hex (Elixir/Erlang)",
  rule: "HEX_MALICIOUS_PACKAGE",
  reads: "mix.lock, mix.exs",
  isFile: (p) => ["mix.lock", "mix.exs"].includes(basenameOf(p)),
  extract(content, p) {
    const out: PackageRef[] = [];
    const lines = content.split(/\r?\n/);
    if (basenameOf(p) === "mix.lock") {
      lines.forEach((raw, i) => {
        // "key": {:hex, :package_name, "1.2.3", ...}: the second atom is the Hex name.
        const m = /\{\s*:hex\s*,\s*:"?([a-z0-9_]+)"?\s*,\s*"([^"]+)"/.exec(raw);
        if (m) out.push({ name: m[1]!, version: exactVersion(m[2]), line: i + 1 });
      });
      return out;
    }
    // Only the body of `defp deps` / `def deps` lists dependencies: aliases
    // such as {:setup, "deps.get"} have the same tuple shape.
    let depsIndent = -1;
    let depsOneLine = false;
    lines.forEach((raw, i) => {
      const line = raw.replace(/#.*$/, "");
      const def = /^(\s*)defp?\s+deps\b(.*)$/.exec(line);
      if (def) {
        depsIndent = def[1]!.length;
        // `defp deps, do: [...]` is a one-line body.
        depsOneLine = /,\s*do\s*:/.test(def[2]!);
      } else if (depsIndent >= 0 && /^\s*end\b/.test(line) && line.length - line.trimStart().length <= depsIndent) {
        depsIndent = -1;
        return;
      }
      if (depsIndent < 0) return;
      for (const t of hexTuples(line)) {
        if (/\b(?:git|github|path|in_umbrella)\s*:/.test(t.rest)) continue;
        const renamed = /\bhex\s*:\s*:"?([a-z0-9_]+)"?/.exec(t.rest);
        out.push({ name: renamed?.[1] ?? t.atom, version: exactVersion(t.requirement.replace(/^==\s*/, "")), line: i + 1 });
      }
      if (depsOneLine) depsIndent = -1;
    });
    return out;
  },
  remediation: "Remove the dependency from mix.exs, run mix deps.unlock and mix deps.clean, and clear the Hex cache",
};

// ---------------------------------------------------------------------------
// CRAN (R)
// ---------------------------------------------------------------------------

const DESCRIPTION_FIELDS = new Set(["Depends", "Imports", "LinkingTo", "Suggests", "Enhances"]);

const cran: EcosystemMatcher = {
  id: "cran",
  label: "CRAN (R)",
  rule: "CRAN_MALICIOUS_PACKAGE",
  reads: "renv.lock, DESCRIPTION",
  isFile: (p) => ["renv.lock", "DESCRIPTION"].includes(basenameOf(p)),
  extract(content, p) {
    const out: PackageRef[] = [];
    if (basenameOf(p) === "renv.lock") {
      const doc = parseJson(content);
      const pkgs = isObject(doc) && isObject(doc.Packages) ? doc.Packages : {};
      const lineOf = orderedLocator(content);
      for (const entry of Object.values(pkgs)) {
        if (!isObject(entry) || typeof entry.Package !== "string") continue;
        // Repository-sourced packages only: GitHub, Bioconductor and local
        // sources are not CRAN identities.
        if (entry.Source !== undefined && entry.Source !== "Repository") continue;
        out.push({ name: entry.Package, version: exactVersion(typeof entry.Version === "string" ? entry.Version : undefined), line: lineOf(`"Package": "${entry.Package}"`) });
      }
      return out;
    }
    // DESCRIPTION: DCF fields, continuation lines start with whitespace.
    // Other tools use the same file name and format; GNU Octave packages even
    // share field names. Only an R package DESCRIPTION (a Package: field, and
    // no dependency on octave itself) names CRAN packages.
    const lines = content.split(/\r?\n/);
    let field = "";
    let isPackage = false;
    let octave = false;
    lines.forEach((raw, i) => {
      const head = /^([A-Za-z][A-Za-z0-9/._-]*):\s*(.*)$/.exec(raw);
      let value: string;
      if (head) { field = head[1]!; value = head[2]!; }
      else if (/^\s/.test(raw)) value = raw;
      else { field = ""; return; }
      if (head && field === "Package" && value.trim()) isPackage = true;
      if (!DESCRIPTION_FIELDS.has(field)) return;
      for (const part of value.split(",")) {
        // Trimmed first: /^\s*name\s*(...)?\s*$/ backtracks quadratically
        // over a long whitespace run that does not end the part.
        const m = /^([A-Za-z][A-Za-z0-9.]*)(?:\s*\(([^)]*)\))?$/.exec(part.trim());
        if (!m || m[1] === "R") continue;
        if (m[1]!.toLowerCase() === "octave") octave = true;
        const exact = /^==\s*(\S+)$/.exec(m[2]?.trim() ?? "");
        out.push({ name: m[1]!, version: exactVersion(exact?.[1]), line: i + 1 });
      }
    });
    return isPackage && !octave ? out : [];
  },
  remediation: "Remove the package from DESCRIPTION / renv.lock, run renv::snapshot(), and remove it from the R library",
};

// ---------------------------------------------------------------------------
// Conan (C/C++)
// ---------------------------------------------------------------------------

/** "name/version[@user/channel][#rev][%ts]" or a version range "name/[>1 <2]". */
function parseConanRef(raw: string): { name: string; version: string | undefined } | null {
  const m = /^\s*([a-z0-9_][a-z0-9_.+-]*)\/([^@#%\s]+)/i.exec(raw);
  if (!m) return null;
  return { name: m[1]!.toLowerCase(), version: m[2]!.startsWith("[") ? undefined : m[2] };
}

const conan: EcosystemMatcher = {
  id: "conan",
  label: "Conan (C/C++)",
  rule: "CONAN_MALICIOUS_PACKAGE",
  reads: "conan.lock, conanfile.txt, conanfile.py",
  isFile: (p) => ["conan.lock", "conanfile.txt", "conanfile.py"].includes(basenameOf(p)),
  extract(content, p) {
    const out: PackageRef[] = [];
    const base = basenameOf(p);
    const push = (raw: string, line: number) => {
      const ref = parseConanRef(raw);
      if (ref) out.push({ name: ref.name, version: ref.version, line });
    };
    if (base === "conan.lock") {
      const doc = parseJson(content);
      if (!isObject(doc)) return out;
      const lineOf = orderedLocator(content);
      for (const key of ["requires", "build_requires", "python_requires", "config_requires"]) {
        const list = doc[key];
        if (Array.isArray(list)) for (const r of list) if (typeof r === "string") push(r, lineOf(r));
      }
      // Conan 1 lockfile: graph_lock.nodes.*.ref
      const nodes = isObject(doc.graph_lock) && isObject(doc.graph_lock.nodes) ? doc.graph_lock.nodes : {};
      for (const node of Object.values(nodes)) {
        if (isObject(node) && typeof node.ref === "string") push(node.ref, lineOf(node.ref));
      }
      return out;
    }
    const lines = content.split(/\r?\n/);
    if (base === "conanfile.txt") {
      let section = "";
      lines.forEach((raw, i) => {
        const line = raw.replace(/#.*$/, "").trim();
        const header = /^\[([a-z_]+)\]$/.exec(line);
        if (header) { section = header[1]!; return; }
        if (["requires", "tool_requires", "build_requires", "test_requires"].includes(section) && line) push(line, i + 1);
      });
      return out;
    }
    // A requires tuple or list may span lines ("requires = (" ... ")"), so an
    // opening bracket left unclosed on a requires line keeps reading string
    // items until its closing bracket.
    const REF = /["']([a-z0-9_][a-z0-9_.+-]*\/[^"']+)["']/gi;
    let closer = "";
    lines.forEach((raw, i) => {
      const line = raw.replace(/#.*$/, "");
      if (closer) {
        const end = line.indexOf(closer);
        for (const m of (end < 0 ? line : line.slice(0, end)).matchAll(REF)) push(m[1]!, i + 1);
        if (end >= 0) closer = "";
        return;
      }
      const req = /\b(?:self\.)?(?:tool_|build_|test_|python_)?requires\b\s*(?:=\s*)?([([])?/.exec(line);
      if (!req) return;
      for (const m of line.matchAll(REF)) push(m[1]!, i + 1);
      const open = req[1];
      if (open) {
        const want = open === "(" ? ")" : "]";
        if (line.indexOf(want, req.index + req[0].length) < 0) closer = want;
      }
    });
    return out;
  },
  remediation: "Remove the requirement from the conanfile, regenerate conan.lock, and remove the package from the Conan cache (conan remove)",
};

// ---------------------------------------------------------------------------
// Helm charts
// ---------------------------------------------------------------------------

/** Chart repository identity: host/path without scheme, lowercase; null for aliases and local charts. */
function normalizeChartRepository(raw: string): string | null {
  // Only http(s) and oci repositories name a published chart; "@alias",
  // "alias:" and "file://" references fail this pattern and are skipped.
  const m = /^(?:https?|oci):\/\/(.+?)\/*$/i.exec(raw.trim());
  if (!m) return null;
  return m[1]!.toLowerCase();
}

const helm: EcosystemMatcher = {
  id: "helm",
  label: "Helm charts",
  rule: "HELM_MALICIOUS_CHART",
  reads: "Chart.yaml, Chart.lock, requirements.yaml (Helm 2)",
  isFile: (p) => {
    const b = basenameOf(p);
    return b === "Chart.yaml" || b === "Chart.lock" || (b === "requirements.yaml" && pathParts(p).length >= 1);
  },
  extract(content) {
    const out: PackageRef[] = [];
    const lines = content.split(/\r?\n/);
    let inDeps = false;
    let current: { name?: string; version?: string; repository?: string; line: number } | null = null;
    const flush = () => {
      if (current?.name && current.repository) {
        const repo = normalizeChartRepository(current.repository);
        if (repo) out.push({ name: `${repo}/${current.name.toLowerCase()}`, version: exactVersion(current.version), line: current.line });
      }
      current = null;
    };
    // Column of the "-" of the first dependency item, and of the keys inside
    // an item. A deeper list (an item's import-values) is not a dependency,
    // and its keys are not the dependency's own.
    let dashCol = -1;
    let keyCol = -1;
    lines.forEach((raw, i) => {
      const text = stripHashComment(raw);
      // A top-level key starts a new section; a "- " list item may also sit at
      // column 0 (Chart.lock writes them that way) and belongs to the section.
      if (/^\S/.test(text) && !text.startsWith("-")) { flush(); inDeps = /^dependencies\s*:/.test(text); dashCol = -1; return; }
      if (!inDeps || !text.trim()) return;
      const item = /^(\s*)-(\s+)(\w+)\s*:\s*(.*)$/.exec(text);
      if (item && (dashCol < 0 || item[1]!.length === dashCol)) {
        flush();
        dashCol = item[1]!.length;
        keyCol = dashCol + 1 + item[2]!.length;
        current = { line: i + 1 };
      }
      const field = /^(\s+)(\w+)\s*:\s*(.*)$/.exec(text);
      const kv = item && item[1]!.length === dashCol ? [item[3]!, item[4]!]
        : field && field[1]!.length === keyCol ? [field[2]!, field[3]!] : null;
      if (kv && current) {
        const key = kv[0]!;
        if (key === "name" || key === "version" || key === "repository") current[key] = unquote(kv[1]!);
      }
    });
    flush();
    return out;
  },
  remediation: "Remove the chart dependency, run helm dependency update, and delete the vendored chart archive under charts/",
};

// ---------------------------------------------------------------------------
// Ansible Galaxy
// ---------------------------------------------------------------------------

const GALAXY_NAME = /^[a-z0-9_]+\.[a-z0-9_]+$/i;

const ansible: EcosystemMatcher = {
  id: "ansible",
  label: "Ansible Galaxy",
  rule: "ANSIBLE_MALICIOUS_CONTENT",
  reads: "requirements.yml / requirements.yaml (collections, roles), galaxy.yml dependencies",
  isFile: (p) => {
    const b = basenameOf(p);
    return b === "requirements.yml" || b === "requirements.yaml" || b === "galaxy.yml";
  },
  extract(content, p) {
    const out: PackageRef[] = [];
    const lines = content.split(/\r?\n/);
    if (basenameOf(p) === "galaxy.yml") {
      let inDeps = false;
      lines.forEach((raw, i) => {
        const text = stripHashComment(raw);
        if (/^\S/.test(text)) { inDeps = /^dependencies\s*:/.test(text); return; }
        if (!inDeps) return;
        const m = /^\s+["']?([a-z0-9_]+\.[a-z0-9_]+)["']?\s*:\s*(.*)$/i.exec(text);
        if (m) out.push({ name: m[1]!.toLowerCase(), version: exactVersion(unquote(m[2]!)), line: i + 1 });
      });
      return out;
    }
    // requirements.yml: collections: / roles: lists, or a bare list of roles.
    let section: "collections" | "roles" | "" = "roles";
    let current: { name?: string; src?: string; version?: string; line: number; source?: string } | null = null;
    const flush = () => {
      // A role's Galaxy-shaped src is what gets installed; its name is then
      // only a local alias. The name counts only when there is no src.
      const id = current?.src ?? current?.name;
      if (id && GALAXY_NAME.test(id) && !current!.source) {
        out.push({ name: id.toLowerCase(), version: exactVersion(current!.version), line: current!.line });
      }
      current = null;
    };
    lines.forEach((raw, i) => {
      const text = stripHashComment(raw);
      const top = /^(collections|roles)\s*:/.exec(text);
      if (top) { flush(); section = top[1] as "collections" | "roles"; return; }
      if (/^\S/.test(text) && !/^-/.test(text)) { flush(); section = ""; return; }
      if (!section) return;
      const bare = /^\s*-\s+["']?([^\s:"']+)["']?\s*$/.exec(text);
      if (bare) { flush(); current = { name: bare[1], line: i + 1 }; flush(); return; }
      const item = /^\s*-\s+(\w+)\s*:\s*(.*)$/.exec(text);
      const field = /^\s+(\w+)\s*:\s*(.*)$/.exec(text);
      if (item) { flush(); current = { line: i + 1 }; }
      const kv = item ?? field;
      if (kv && current) {
        const key = kv[1]!;
        const value = unquote(kv[2]!);
        // A role "src" may be a Galaxy name or a git/URL source.
        if (key === "name") current.name ??= value;
        else if (key === "src" && GALAXY_NAME.test(value)) {
          if (section === "roles") current.src ??= value;
          else current.name ??= value;
        }
        else if (key === "src") current.source = value;
        else if (key === "version") current.version = value;
        else if (key === "source" || key === "type") {
          if (key === "type" && !/^galaxy$/i.test(value)) current.source = value;
          if (key === "source" && !/galaxy\.ansible\.com/i.test(value)) current.source = value;
        }
      }
    });
    flush();
    return out;
  },
  remediation: "Remove the collection or role from requirements.yml, delete it from the Ansible collections/roles path, and review hosts it ran against",
};

// ---------------------------------------------------------------------------
// Homebrew
// ---------------------------------------------------------------------------

const homebrew: EcosystemMatcher = {
  id: "homebrew",
  label: "Homebrew",
  rule: "HOMEBREW_MALICIOUS_PACKAGE",
  reads: "Brewfile, Brewfile.lock.json",
  isFile: (p) => ["Brewfile", "Brewfile.lock.json"].includes(basenameOf(p)),
  extract(content, p) {
    const out: PackageRef[] = [];
    if (basenameOf(p) === "Brewfile.lock.json") {
      const doc = parseJson(content);
      const entries = isObject(doc) && isObject(doc.entries) ? doc.entries : {};
      const lineOf = orderedLocator(content);
      for (const [kind, map] of Object.entries(entries)) {
        if (!isObject(map) || !["brew", "cask", "tap"].includes(kind)) continue;
        for (const [name, info] of Object.entries(map)) {
          const version = isObject(info) && typeof info.version === "string" ? info.version : undefined;
          const id = kind === "brew" ? name.toLowerCase() : `${kind}:${name.toLowerCase()}`;
          out.push({ name: id, version: exactVersion(version), line: lineOf(`"${name}"`) });
        }
      }
      return out;
    }
    content.split(/\r?\n/).forEach((raw, i) => {
      const m = /^\s*(brew|cask|tap)\s+["']([^"']+)["']/.exec(raw.replace(/#.*$/, ""));
      if (!m) return;
      const name = m[2]!.toLowerCase();
      out.push({ name: m[1] === "brew" ? name : `${m[1]}:${name}`, version: undefined, line: i + 1 });
    });
    return out;
  },
  remediation: "Uninstall it (brew uninstall), remove it and its tap from the Brewfile, and rotate credentials available on machines that installed it",
};

// ---------------------------------------------------------------------------
// Browser extensions (Chrome / Edge / Firefox)
// ---------------------------------------------------------------------------

const CHROMIUM_ID = /^[a-p]{32}$/;

const browser: EcosystemMatcher = {
  id: "chrome",
  label: "Browser extensions (Chrome, Edge, Firefox)",
  rule: "BROWSER_MALICIOUS_EXTENSION",
  reads: "Chromium/Edge/Firefox enterprise policies (ExtensionInstallForcelist, ExtensionSettings), installed Chromium extension manifests (Extensions/<id>/<version>/manifest.json), Firefox extension manifests (gecko id)",
  isFile: (p) => {
    const parts = pathParts(p);
    const b = parts[parts.length - 1] ?? "";
    if (b === "policies.json") return true;
    if (b === "manifest.json") return true;
    const posix = parts.join("/").toLowerCase();
    return b.endsWith(".json") && /\/policies\/(?:managed|recommended)\//.test(`/${posix}`);
  },
  extract(content, p) {
    const out: PackageRef[] = [];
    const doc = parseJson(content);
    if (!isObject(doc)) return out;
    const parts = pathParts(p);
    const lineOf = orderedLocator(content);
    const chromium = (id: string, version: string | undefined, needle: string) => {
      const lower = id.toLowerCase();
      if (CHROMIUM_ID.test(lower)) out.push({ name: lower, version, line: lineOf(needle), ecosystems: ["chrome", "edge"] });
    };
    const firefox = (id: string, version: string | undefined) => {
      if (id && id !== "*" && id.length <= 200) out.push({ name: id, version, line: lineOf(id), ecosystems: ["firefox"] });
    };

    if (basenameOf(p) === "manifest.json") {
      const version = typeof doc.version === "string" ? exactVersion(doc.version) : undefined;
      // Firefox: the gecko id is the extension's identity.
      const bss = isObject(doc.browser_specific_settings) ? doc.browser_specific_settings
        : isObject(doc.applications) ? doc.applications : undefined;
      if (bss && isObject(bss.gecko) && typeof bss.gecko.id === "string") firefox(bss.gecko.id, version);
      // Installed Chromium extension: .../Extensions/<id>/<version>_<n>/manifest.json
      const dir = parts[parts.length - 3];
      const verDir = parts[parts.length - 2];
      // The version directory is what marks an INSTALLED copy; chromium()
      // validates the id itself.
      if (dir && verDir && /^\d[\d.]*(?:_\d+)?$/.test(verDir) && typeof doc.manifest_version === "number") {
        chromium(dir, version, "\"version\"");
      }
      return out;
    }

    // Policy files: Chromium (Chrome/Edge) at the top level, Firefox under "policies".
    const policies = isObject(doc.policies) ? doc.policies : doc;
    const forcelist = policies.ExtensionInstallForcelist;
    if (Array.isArray(forcelist)) {
      for (const entry of forcelist) if (typeof entry === "string") chromium(entry.split(";")[0]!, undefined, entry);
    }
    const settings = policies.ExtensionSettings;
    if (isObject(settings)) {
      for (const key of Object.keys(settings)) {
        for (const id of key.split(",")) {
          const trimmed = id.trim();
          if (CHROMIUM_ID.test(trimmed.toLowerCase())) chromium(trimmed, undefined, trimmed);
          else if (isObject(doc.policies)) firefox(trimmed, undefined);
        }
      }
    }
    // Firefox Extensions.Locked lists add-on ids that users cannot remove.
    // Extensions.Install holds download URLs, not ids, so it is not read.
    if (isObject(doc.policies) && isObject(policies.Extensions) && Array.isArray(policies.Extensions.Locked)) {
      for (const id of policies.Extensions.Locked) if (typeof id === "string") firefox(id.trim(), undefined);
    }
    return out;
  },
  remediation: "Remove the extension from every browser profile and from managed policies, and rotate credentials and sessions used in that browser",
};

// ---------------------------------------------------------------------------
// JetBrains plugins
// ---------------------------------------------------------------------------

const jetbrains: EcosystemMatcher = {
  id: "jetbrains",
  label: "JetBrains plugins",
  rule: "JETBRAINS_MALICIOUS_PLUGIN",
  reads: ".idea/externalDependencies.xml (required plugins), META-INF/plugin.xml (plugin descriptor)",
  isFile: (p) => {
    const parts = pathParts(p);
    const b = parts[parts.length - 1] ?? "";
    return (b === "externalDependencies.xml" && parts[parts.length - 2] === ".idea")
      || (b === "plugin.xml" && parts[parts.length - 2] === "META-INF");
  },
  extract(content, p) {
    const out: PackageRef[] = [];
    const text = stripXmlComments(content);
    if (basenameOf(p) === "externalDependencies.xml") {
      const lineOf = orderedLocator(content);
      // Walk the <plugin tags by index: a regex with [^>]* rescans to the next
      // ">" from every "<plugin", which is quadratic when none follows.
      for (let at = text.indexOf("<plugin"); at >= 0;) {
        const close = text.indexOf(">", at);
        const tagEnd = close < 0 ? text.length : close;
        const tag = text.slice(at, tagEnd);
        const m = /^<plugin\b[^]*?\bid\s*=\s*["']([^"']+)["']/.exec(tag);
        if (m) out.push({ name: m[1]!, version: undefined, line: lineOf(m[1]!) });
        if (close < 0) break;
        at = text.indexOf("<plugin", close);
      }
      return out;
    }
    const id = /<id>\s*([^<\s]+)\s*<\/id>/.exec(text)?.[1];
    const version = /<version>\s*([^<\s]+)\s*<\/version>/.exec(text)?.[1];
    if (id) out.push({ name: id, version: exactVersion(version), line: lineOfNeedle(content, `<id>`) });
    return out;
  },
  remediation: "Uninstall the plugin from every IDE installation, remove it from .idea/externalDependencies.xml, and rotate API keys and tokens the IDE had access to",
};

// ---------------------------------------------------------------------------

export const ECOSYSTEM_MATCHERS: readonly EcosystemMatcher[] = [
  swift, cocoapods, hex, cran, conan, helm, ansible, homebrew, browser, jetbrains,
];

/** True when at least one registry matcher reads this file. */
export function isRegistryFile(relativePath: string): boolean {
  return ECOSYSTEM_MATCHERS.some((m) => m.isFile(relativePath));
}

/**
 * Scan one file with every registry matcher that reads it.
 */
export function scanRegistryFile(content: string, relativePath: string, feed?: FeedIOC[]): Finding[] {
  const iocFeed = feed ?? loadThreatIntel();
  const findings: Finding[] = [];
  const file = relativePath.replace(/\\/g, "/");
  for (const matcher of ECOSYSTEM_MATCHERS) {
    if (!matcher.isFile(file)) continue;
    const seen = new Set<string>();
    for (const ref of matcher.extract(content, file)) {
      for (const eco of ref.ecosystems ?? [matcher.id]) {
        const key = `${eco}:${ref.name}@${ref.version ?? ""}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const ioc = matchPackageIOC(eco, ref.name, ref.version, iocFeed);
        if (!ioc) continue;
        findings.push({
          rule: matcher.rule,
          description: `Known malicious ${matcher.label} entry: ${ref.name}${ref.version ? `@${ref.version}` : ""}${ref.ecosystems ? ` (${eco})` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
          severity: ioc.severity,
          file,
          line: ref.line,
          match: ref.version ? `${ref.name}@${ref.version}` : ref.name,
          confidence: ioc.confidence,
          category: "malware",
          recommendation: `${matcher.remediation}. This identity is listed in threat intelligence feeds.`,
        });
        break; // first matching registry wins for a multi-registry identity
      }
    }
  }
  return findings;
}
