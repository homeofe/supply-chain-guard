/**
 * Terraform / OpenTofu provider scanner.
 *
 * Resolves the providers a configuration pulls in and matches them against
 * `terraform:<namespace>/<type>` feed entries. A malicious provider runs as a
 * native plugin during `terraform init` / `plan`, with the credentials of
 * whoever runs it, so the provider address is the dependency identity that
 * matters here, exactly as a module path is for go.sum.
 *
 * Three sources are read:
 *   - `.tf`: `source = "ns/type"` in a required_providers block
 *   - `.tf.json`: the same attribute in JSON syntax
 *   - `.terraform.lock.hcl`: `provider "host/ns/type" { version = "x" }`,
 *     which also carries the exact resolved version
 *
 * Registry MODULES are matched too, against `tfmodule:<namespace>/<name>/<system>`
 * entries: from `module` blocks (source + version) and from the installed
 * module manifest `.terraform/modules/modules.json`, which records the exact
 * version `terraform init` fetched. A module address is a different registry
 * object from a provider address, hence its own prefix.
 *
 * Only public-registry addresses are resolved: no host (Terraform's default of
 * registry.terraform.io), registry.terraform.io, or registry.opentofu.org. A
 * private registry host names a different provider that merely shares the
 * namespace and type, so matching it would report someone else's plugin.
 */

import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";

const LOCK_FILE = ".terraform.lock.hcl";

/** Registry hosts whose namespaces are the ones the feed describes. */
const PUBLIC_REGISTRY_HOSTS = new Set(["registry.terraform.io", "registry.opentofu.org"]);

/** Namespace and type labels: letters, digits, hyphens and underscores. */
const LABEL = /^[a-z0-9][a-z0-9_-]*$/i;

export interface TerraformProviderRef {
  /** Lowercased `namespace/type` on a public registry. */
  address: string;
  /** Exact version, only known from the lock file. */
  version: string | undefined;
  /** 1-based line of the source attribute or provider block. */
  line: number;
}

/**
 * Check if a file declares or locks Terraform providers.
 */
export function isTerraformProviderFile(relativePath: string): boolean {
  const parts = relativePath.replace(/\\/g, "/").split("/");
  const basename = parts[parts.length - 1] ?? "";
  if (basename === MODULE_MANIFEST) return parts[parts.length - 2] === "modules" && parts[parts.length - 3] === ".terraform";
  return basename === LOCK_FILE || basename.endsWith(".tf") || basename.endsWith(".tf.json");
}

const MODULE_MANIFEST = "modules.json";

export interface TerraformModuleRef {
  /** Lowercased `namespace/name/system` on a public registry. */
  address: string;
  /** Exact version: a `version = "1.2.3"` attribute or the installed manifest. */
  version: string | undefined;
  line: number;
}

/**
 * Module source: [public-host/]namespace/name/system, nothing else. A
 * `//subdir` suffix selects a submodule of the same registry module
 * (`terraform-aws-modules/iam/aws//modules/iam-user`) and is dropped.
 */
export function parseModuleAddress(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed.includes("://")) return null;
  const parts = trimmed.split("//")[0]!.split("/");
  if (parts.length === 4) {
    if (!PUBLIC_REGISTRY_HOSTS.has((parts[0] ?? "").toLowerCase())) return null;
    parts.shift();
  }
  if (parts.length !== 3 || !parts.every((p) => LABEL.test(p))) return null;
  return parts.join("/").toLowerCase();
}

const EXACT_MODULE_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/**
 * Extract public-registry modules from `module` blocks or the installed
 * module manifest. A version constraint is not a version; only an exact
 * `version = "1.2.3"` is kept.
 */
export function extractTerraformModules(content: string, relativePath: string): TerraformModuleRef[] {
  const basename = relativePath.replace(/\\/g, "/").split("/").pop() ?? "";
  if (basename === MODULE_MANIFEST) {
    let doc: unknown;
    try { doc = JSON.parse(content); } catch { return []; }
    const modules = (doc as { Modules?: unknown })?.Modules;
    if (!Array.isArray(modules)) return [];
    const out: TerraformModuleRef[] = [];
    for (const m of modules) {
      const source = (m as { Source?: unknown })?.Source;
      const version = (m as { Version?: unknown })?.Version;
      const address = typeof source === "string" ? parseModuleAddress(source) : null;
      if (address) out.push({ address, version: typeof version === "string" && EXACT_MODULE_VERSION.test(version) ? version : undefined, line: 1 });
    }
    return out;
  }
  if (basename.endsWith(".tf.json")) {
    // module: { name: { source, version } } or an array of such objects.
    let doc: unknown;
    try { doc = JSON.parse(content); } catch { return []; }
    const out: TerraformModuleRef[] = [];
    const lineOf = jsonStringLines(content);
    for (const block of jsonBlocks((doc as Record<string, unknown> | null)?.module)) {
      for (const body of jsonBlocks(Object.values(block))) {
        const source = body.source;
        const version = body.version;
        const address = typeof source === "string" ? parseModuleAddress(source) : null;
        if (address) {
          out.push({
            address,
            version: typeof version === "string" && EXACT_MODULE_VERSION.test(version.trim()) ? version.trim() : undefined,
            line: lineOf(source as string),
          });
        }
      }
    }
    return out;
  }
  if (!basename.endsWith(".tf")) return [];
  const out: TerraformModuleRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*module\s+"[^"]*"\s*\{/.test(lines[i] ?? "")) continue;
    // Collect the block body by brace depth (a one-line block included).
    // Modules do not nest, so scanning resumes after the block: each line is
    // read once, and an unclosed block cannot make the scan quadratic.
    let depth = 0;
    let body = "";
    let j = i;
    for (; j < lines.length; j++) {
      const line = lines[j] ?? "";
      body += line + "\n";
      depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      if (depth <= 0) break;
    }
    const source = /\bsource\s*=\s*"([^"]*)"/.exec(body)?.[1];
    const version = /\bversion\s*=\s*"([^"]*)"/.exec(body)?.[1];
    const address = source ? parseModuleAddress(source) : null;
    if (address) out.push({ address, version: version && EXACT_MODULE_VERSION.test(version.trim()) ? version.trim() : undefined, line: i + 1 });
    i = j;
  }
  return out;
}

/**
 * Line lookup for decoded JSON string values: the line of the first string
 * literal with that value, built in one pass over the text.
 *
 * It replaces lineOfNeedle(content, `"${source}"`) per module or provider,
 * which searched the whole file once per entry: quadratic in the number of
 * distinct sources, about 75 s for a 5 MB .tf.json (6.3.0 pre-release review).
 * Matching the decoded value also finds a source written with JSON escapes
 * (`\/`), which the raw search reported as line 1.
 */
export function jsonStringLines(content: string): (value: string) => number {
  const first = new Map<string, number>();
  let line = 1;
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (ch === "\n") { line++; continue; }
    if (ch !== '"') continue;
    const startLine = line;
    let j = i + 1;
    let escaped = false;
    for (; j < content.length; j++) {
      const c = content[j];
      if (c === "\n") line++;
      if (escaped) { escaped = false; continue; }
      if (c === "\\") { escaped = true; continue; }
      if (c === '"') break;
    }
    const raw = content.slice(i, j + 1);
    let value: string;
    try {
      value = JSON.parse(raw) as string;
    } catch {
      value = raw.slice(1, -1);
    }
    if (!first.has(value)) first.set(value, startLine);
    i = j;
  }
  return (value) => first.get(value) ?? 1;
}

/**
 * The block label a `{` opens: the identifier right before it, ignoring
 * spaces, or "{" when there is none (`docker = {`, `"name" {`). Scans back
 * only over the spaces and word next to this brace, so a line is read in
 * linear time.
 */
function blockLabelBefore(line: string, brace: number): string {
  let j = brace - 1;
  while (j >= 0 && (line[j] === " " || line[j] === "\t")) j--;
  const end = j + 1;
  while (j >= 0 && /[\w-]/.test(line[j]!)) j--;
  const word = line.slice(j + 1, end);
  return /^[A-Za-z_][\w-]*$/.test(word) ? word : "{";
}

/** HCL-JSON blocks: an object, or an array of objects. */
function jsonBlocks(value: unknown): Record<string, unknown>[] {
  const list = Array.isArray(value) ? value : [value];
  return list.filter((v): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v));
}

/**
 * Parse a provider source address into a public-registry `namespace/type`.
 *
 * Returns null for anything that is not one: module sources share the `source`
 * attribute name, so a local path, a URL, a `git::` source, a three-part module
 * address (ns/name/system) or a private host must all fall out here rather
 * than be reported as a provider.
 */
export function parseProviderAddress(raw: string): string | null {
  // Paths ("./x", "../x", "~/x") and URL or getter forms ("git::", "https://")
  // are rejected by the part count, the host allow-list or the label rule
  // below: ".", "~" and ":" are never valid in a namespace or type.
  const parts = raw.trim().split("/");
  let ns: string | undefined;
  let type: string | undefined;
  if (parts.length === 2) {
    [ns, type] = parts;
  } else if (parts.length === 3) {
    // host/ns/type. The allow-list is also what rejects a three-part module
    // address (ns/name/system): its first segment is never a registry host.
    if (!PUBLIC_REGISTRY_HOSTS.has((parts[0] ?? "").toLowerCase())) return null;
    [, ns, type] = parts;
  } else {
    return null;
  }
  if (!ns || !type || !LABEL.test(ns) || !LABEL.test(type)) return null;
  return `${ns}/${type}`.toLowerCase();
}

/**
 * Extract every public-registry provider a Terraform file references.
 */
export function extractTerraformProviders(
  content: string,
  relativePath: string,
): TerraformProviderRef[] {
  const lines = content.split(/\r?\n/);
  const basename = relativePath.replace(/\\/g, "/").split("/").pop() ?? "";
  const refs: TerraformProviderRef[] = [];

  if (basename === MODULE_MANIFEST) return refs;

  if (basename === LOCK_FILE) {
    for (let i = 0; i < lines.length; i++) {
      const block = /^\s*provider\s+"([^"]+)"\s*\{/.exec(lines[i] ?? "");
      if (!block) continue;
      const address = parseProviderAddress(block[1] ?? "");
      let version: string | undefined;
      // The block body holds a hashes list closed by "]", so the first line
      // that starts with "}" is the end of this provider block. Scanning
      // resumes after it, so each line is read once.
      let j = i + 1;
      for (; j < lines.length && !/^\s*\}/.test(lines[j] ?? ""); j++) {
        const v = /^\s*version\s*=\s*"([^"]+)"/.exec(lines[j] ?? "");
        if (v) version = v[1];
      }
      if (address) refs.push({ address, version, line: i + 1 });
      i = j;
    }
    return refs;
  }

  if (basename.endsWith(".tf.json")) {
    // terraform: { required_providers: { name: { source } } }, each level an
    // object or an array of objects.
    let doc: unknown;
    try { doc = JSON.parse(content); } catch { return refs; }
    const lineOf = jsonStringLines(content);
    for (const tf of jsonBlocks((doc as Record<string, unknown> | null)?.terraform)) {
      for (const rp of jsonBlocks(tf.required_providers)) {
        for (const provider of jsonBlocks(Object.values(rp))) {
          const source = provider.source;
          const address = typeof source === "string" ? parseProviderAddress(source) : null;
          if (address) refs.push({ address, version: undefined, line: lineOf(source as string) });
        }
      }
    }
    return refs;
  }

  // .tf: `source = "ns/type"` is a provider address ONLY inside
  // terraform { required_providers { ... } }. Everywhere else `source` is a
  // file, a module or an object key (provisioner "file", aws_s3_object,
  // local_file), and reading it as a provider reported someone's relative path.
  // `inside` counts the open required_providers blocks on the stack, so the
  // check per source is constant rather than a walk of the whole stack.
  //
  // A line is read left to right: a `source` counts if a required_providers
  // block is open AT ITS POSITION, and each `{` is labelled by the word right
  // before it. Checking the line's sources before counting its braces, and
  // labelling only a line's first brace, missed the valid one-line form
  // `required_providers { docker = { source = "ns/type" } }` (6.3.0
  // pre-release review).
  const stack: string[] = [];
  let inside = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const sources = [...line.matchAll(/\bsource\s*=\s*"([^"]*)"/g)];
    let next = 0;
    for (let k = 0; k < line.length; k++) {
      for (; next < sources.length && sources[next]!.index! <= k; next++) {
        if (inside === 0) continue;
        const address = parseProviderAddress(sources[next]![1] ?? "");
        if (address) refs.push({ address, version: undefined, line: i + 1 });
      }
      const ch = line[k];
      if (ch === "{") {
        const opened = blockLabelBefore(line, k);
        stack.push(opened);
        if (opened === "required_providers") inside++;
      } else if (ch === "}" && stack.pop() === "required_providers") {
        inside--;
      }
    }
  }
  return refs;
}

/**
 * Scan a Terraform file for providers matching `terraform:` feed IOCs.
 */
export function scanTerraformContent(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const findings: Finding[] = [];
  const iocFeed = feed ?? loadThreatIntel();
  const seen = new Set<string>();

  for (const ref of extractTerraformProviders(content, relativePath)) {
    const key = `${ref.address}@${ref.version ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const ioc = matchPackageIOC("terraform", ref.address, ref.version, iocFeed);
    if (!ioc) continue;

    findings.push({
      rule: "TERRAFORM_MALICIOUS_PROVIDER",
      description: `Known malicious Terraform provider: ${ref.address}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
      severity: ioc.severity,
      file: relativePath,
      line: ref.line,
      match: ref.version ? `${ref.address}@${ref.version}` : ref.address,
      confidence: ioc.confidence,
      category: "malware",
      recommendation: `Remove the ${ref.address} provider, delete the cached plugin under .terraform/providers, `
        + "rotate every credential available to the runs that initialised it, and audit the state it touched. "
        + "This provider is listed in threat intelligence feeds.",
    });
  }

  for (const ref of extractTerraformModules(content, relativePath)) {
    const key = `module:${ref.address}@${ref.version ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const ioc = matchPackageIOC("tfmodule", ref.address, ref.version, iocFeed);
    if (!ioc) continue;
    findings.push({
      rule: "TERRAFORM_MALICIOUS_MODULE",
      description: `Known malicious Terraform module: ${ref.address}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
      severity: ioc.severity,
      file: relativePath,
      line: ref.line,
      match: ref.version ? `${ref.address}@${ref.version}` : ref.address,
      confidence: ioc.confidence,
      category: "malware",
      recommendation: `Remove the ${ref.address} module, delete .terraform/modules, rotate every credential available `
        + "to the runs that applied it, and review the resources it created. This module is listed in threat intelligence feeds.",
    });
  }

  return findings;
}
