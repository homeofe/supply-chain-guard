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

/** Line number (1-based) of the first line containing `needle`, else 1. */
function lineOf(content: string, needle: string): number {
  const idx = content.indexOf(needle);
  if (idx < 0) return 1;
  let line = 1;
  for (let i = 0; i < idx; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
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
      for (const pin of pins) {
        if (!isObject(pin)) continue;
        // Local pins carry a path, which normalizeRepositoryUrl rejects.
        const url = typeof pin.location === "string" ? pin.location
          : typeof pin.repositoryURL === "string" ? pin.repositoryURL : undefined;
        const name = url ? normalizeRepositoryUrl(url) : null;
        const state = isObject(pin.state) ? pin.state : {};
        if (name) out.push({ name, version: exactVersion(typeof state.version === "string" ? state.version : undefined), line: lineOf(content, url!) });
      }
      return out;
    }
    content.split(/\r?\n/).forEach((raw, i) => {
      // Whole-line comments only: a "//" inside "https://" is not a comment.
      if (raw.trim().startsWith("//")) return;
      const line = raw;
      for (const m of line.matchAll(/\.package\s*\(\s*(?:name\s*:\s*"[^"]*"\s*,\s*)?url\s*:\s*"([^"]+)"([^)]*)\)?/g)) {
        const name = normalizeRepositoryUrl(m[1]!);
        const exact = /(?:exact\s*:\s*|\.exact\s*\(\s*)"([^"]+)"/.exec(m[2] ?? "");
        if (name) out.push({ name, version: exactVersion(exact?.[1]), line: i + 1 });
      }
    });
    return out;
  },
  remediation: "Remove the package from Package.swift, delete it from Package.resolved and the SwiftPM cache (~/Library/Caches/org.swift.swiftpm)",
};

// ---------------------------------------------------------------------------
// CocoaPods
// ---------------------------------------------------------------------------

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
      let inPods = false;
      lines.forEach((raw, i) => {
        if (/^\S/.test(raw)) inPods = raw.trim() === "PODS:";
        if (!inPods) return;
        // Top-level entries are exact ("  - Name/Sub (1.2.3)"); nested
        // dependency lines carry constraints and are one level deeper.
        const m = /^ {2}- "?([^\s"(]+)"? \(([^)]+)\):?$/.exec(raw);
        if (m) out.push({ name: m[1]!.split("/")[0]!.toLowerCase(), version: exactVersion(m[2]), line: i + 1 });
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
    lines.forEach((raw, i) => {
      const line = raw.replace(/#.*$/, "");
      for (const m of line.matchAll(/\{\s*:([a-z0-9_]+)\s*,\s*"([^"]+)"([^}]*)\}/g)) {
        const rest = m[3] ?? "";
        if (/\b(?:git|github|path|in_umbrella)\s*:/.test(rest)) continue;
        const renamed = /\bhex\s*:\s*:"?([a-z0-9_]+)"?/.exec(rest);
        out.push({ name: renamed?.[1] ?? m[1]!, version: exactVersion(m[2]!.replace(/^==\s*/, "")), line: i + 1 });
      }
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
      for (const entry of Object.values(pkgs)) {
        if (!isObject(entry) || typeof entry.Package !== "string") continue;
        // Repository-sourced packages only: GitHub, Bioconductor and local
        // sources are not CRAN identities.
        if (entry.Source !== undefined && entry.Source !== "Repository") continue;
        out.push({ name: entry.Package, version: exactVersion(typeof entry.Version === "string" ? entry.Version : undefined), line: lineOf(content, `"Package": "${entry.Package}"`) });
      }
      return out;
    }
    // DESCRIPTION: DCF fields, continuation lines start with whitespace.
    const lines = content.split(/\r?\n/);
    let field = "";
    lines.forEach((raw, i) => {
      const head = /^([A-Za-z][A-Za-z0-9/._-]*):\s*(.*)$/.exec(raw);
      let value: string;
      if (head) { field = head[1]!; value = head[2]!; }
      else if (/^\s/.test(raw)) value = raw;
      else { field = ""; return; }
      if (!DESCRIPTION_FIELDS.has(field)) return;
      for (const part of value.split(",")) {
        const m = /^\s*([A-Za-z][A-Za-z0-9.]*)\s*(?:\(\s*([^)]*)\))?\s*$/.exec(part);
        if (!m || m[1] === "R") continue;
        const exact = /^==\s*(\S+)$/.exec(m[2]?.trim() ?? "");
        out.push({ name: m[1]!, version: exactVersion(exact?.[1]), line: i + 1 });
      }
    });
    return out;
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
      for (const key of ["requires", "build_requires", "python_requires", "config_requires"]) {
        const list = doc[key];
        if (Array.isArray(list)) for (const r of list) if (typeof r === "string") push(r, lineOf(content, r));
      }
      // Conan 1 lockfile: graph_lock.nodes.*.ref
      const nodes = isObject(doc.graph_lock) && isObject(doc.graph_lock.nodes) ? doc.graph_lock.nodes : {};
      for (const node of Object.values(nodes)) {
        if (isObject(node) && typeof node.ref === "string") push(node.ref, lineOf(content, node.ref));
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
    lines.forEach((raw, i) => {
      const line = raw.replace(/#.*$/, "");
      const isRequireLine = /\b(?:self\.)?(?:tool_|build_|test_|python_)?requires\b/.test(line);
      if (!isRequireLine) return;
      for (const m of line.matchAll(/["']([a-z0-9_][a-z0-9_.+-]*\/[^"']+)["']/gi)) push(m[1]!, i + 1);
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
    lines.forEach((raw, i) => {
      const text = raw.replace(/\s+#.*$/, "");
      // A top-level key starts a new section; a "- " list item may also sit at
      // column 0 (Chart.lock writes them that way) and belongs to the section.
      if (/^\S/.test(text) && !text.startsWith("-")) { flush(); inDeps = /^dependencies\s*:/.test(text); return; }
      if (!inDeps || !text.trim()) return;
      const item = /^\s*-\s+(\w+)\s*:\s*(.*)$/.exec(text);
      const field = /^\s+(\w+)\s*:\s*(.*)$/.exec(text);
      if (item) { flush(); current = { line: i + 1 }; }
      const kv = item ?? field;
      if (kv && current) {
        const key = kv[1]!;
        if (key === "name" || key === "version" || key === "repository") current[key] = unquote(kv[2]!);
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
        const text = raw.replace(/\s+#.*$/, "");
        if (/^\S/.test(text)) { inDeps = /^dependencies\s*:/.test(text); return; }
        if (!inDeps) return;
        const m = /^\s+["']?([a-z0-9_]+\.[a-z0-9_]+)["']?\s*:\s*(.*)$/i.exec(text);
        if (m) out.push({ name: m[1]!.toLowerCase(), version: exactVersion(unquote(m[2]!)), line: i + 1 });
      });
      return out;
    }
    // requirements.yml: collections: / roles: lists, or a bare list of roles.
    let section: "collections" | "roles" | "" = "roles";
    let current: { name?: string; version?: string; line: number; source?: string } | null = null;
    const flush = () => {
      if (current?.name && GALAXY_NAME.test(current.name) && !current.source) {
        out.push({ name: current.name.toLowerCase(), version: exactVersion(current.version), line: current.line });
      }
      current = null;
    };
    lines.forEach((raw, i) => {
      const text = raw.replace(/\s+#.*$/, "");
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
        if (key === "name" || (key === "src" && GALAXY_NAME.test(value))) current.name ??= value;
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
      for (const [kind, map] of Object.entries(entries)) {
        if (!isObject(map) || !["brew", "cask", "tap"].includes(kind)) continue;
        for (const [name, info] of Object.entries(map)) {
          const version = isObject(info) && typeof info.version === "string" ? info.version : undefined;
          const id = kind === "brew" ? name.toLowerCase() : `${kind}:${name.toLowerCase()}`;
          out.push({ name: id, version: exactVersion(version), line: lineOf(content, `"${name}"`) });
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
    const chromium = (id: string, version: string | undefined, needle: string) => {
      const lower = id.toLowerCase();
      if (CHROMIUM_ID.test(lower)) out.push({ name: lower, version, line: lineOf(content, needle), ecosystems: ["chrome", "edge"] });
    };
    const firefox = (id: string, version: string | undefined) => {
      if (id && id !== "*" && id.length <= 200) out.push({ name: id, version, line: lineOf(content, id), ecosystems: ["firefox"] });
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
    const text = content.replace(/<!--[\s\S]*?-->/g, "");
    if (basenameOf(p) === "externalDependencies.xml") {
      for (const m of text.matchAll(/<plugin\b[^>]*\bid\s*=\s*["']([^"']+)["']/g)) {
        out.push({ name: m[1]!, version: undefined, line: lineOf(content, m[1]!) });
      }
      return out;
    }
    const id = /<id>\s*([^<\s]+)\s*<\/id>/.exec(text)?.[1];
    const version = /<version>\s*([^<\s]+)\s*<\/version>/.exec(text)?.[1];
    if (id) out.push({ name: id, version: exactVersion(version), line: lineOf(content, `<id>`) });
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
