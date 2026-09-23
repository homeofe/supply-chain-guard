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
export function isTerraformProviderFile(basename: string): boolean {
  return basename === LOCK_FILE || basename.endsWith(".tf") || basename.endsWith(".tf.json");
}

/**
 * Parse a provider source address into a public-registry `namespace/type`.
 *
 * Returns null for anything that is not one: module sources share the `source`
 * attribute name, so a local path, a URL, a `git::` source, a three-part module
 * address (ns/name/system) or a private host must all fall out here rather
 * than be reported as a provider.
 */
function parseProviderAddress(raw: string): string | null {
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

  if (basename === LOCK_FILE) {
    for (let i = 0; i < lines.length; i++) {
      const block = /^\s*provider\s+"([^"]+)"\s*\{/.exec(lines[i] ?? "");
      if (!block) continue;
      const address = parseProviderAddress(block[1] ?? "");
      let version: string | undefined;
      // The block body holds a hashes list closed by "]", so the first line
      // that starts with "}" is the end of this provider block.
      for (let j = i + 1; j < lines.length && !/^\s*\}/.test(lines[j] ?? ""); j++) {
        const v = /^\s*version\s*=\s*"([^"]+)"/.exec(lines[j] ?? "");
        if (v) version = v[1];
      }
      if (address) refs.push({ address, version, line: i + 1 });
    }
    return refs;
  }

  const attribute = basename.endsWith(".tf.json")
    ? /"source"\s*:\s*"([^"]*)"/g
    : /\bsource\s*=\s*"([^"]*)"/g;
  for (let i = 0; i < lines.length; i++) {
    for (const m of (lines[i] ?? "").matchAll(attribute)) {
      const address = parseProviderAddress(m[1] ?? "");
      if (address) refs.push({ address, version: undefined, line: i + 1 });
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

  return findings;
}
