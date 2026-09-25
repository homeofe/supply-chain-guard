/**
 * VS Code / Open VSX extension identity matching.
 *
 * Matches extension IDs (`publisher.name`, optionally `@version`) against
 * `vscode:` (VS Code Marketplace) and `openvsx:` (Open VSX) feed entries. The
 * two registries are separate namespaces: the same `publisher.name` can belong
 * to different people on each, so an entry names the registry it came from.
 *
 * Where a directory declares extensions:
 *   - `.vscode/extensions.json`: workspace `recommendations`
 *   - `devcontainer.json` / `.devcontainer.json`:
 *     `customizations.vscode.extensions`, and the legacy top-level `extensions`
 *   - an installed or packaged extension manifest: a `package.json` with a
 *     `publisher` and an `engines.vscode` constraint
 *
 * None of these say which registry the editor resolves against (VS Code uses
 * the Marketplace; VSCodium, Cursor and Windsurf use Open VSX), so both are
 * checked. A `.vsix` scan with an explicit `--registry` checks only that one.
 *
 * A recommendation carries no version, so a version-pinned entry (a hijacked
 * legitimate extension) fires only where a version is actually known: a
 * devcontainer `id@version` pin, a manifest, or a `.vsix`.
 */

import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { isJsonObject } from "./json-utils.js";
import { stripJsonc } from "./mcp-scanner.js";

export type ExtensionRegistry = "marketplace" | "openvsx";

const FEED_PREFIX: Record<ExtensionRegistry, string> = {
  marketplace: "vscode",
  openvsx: "openvsx",
};

const REGISTRY_LABEL: Record<ExtensionRegistry, string> = {
  marketplace: "VS Code Marketplace",
  openvsx: "Open VSX",
};

const BOTH_REGISTRIES: readonly ExtensionRegistry[] = ["marketplace", "openvsx"];

/** Same identifier rule the registry download path enforces (vscode-scanner.ts). */
const EXTENSION_ID = /^([A-Za-z0-9][A-Za-z0-9_-]{0,127})\.([A-Za-z0-9][A-Za-z0-9_-]{0,127})(?:@([A-Za-z0-9][A-Za-z0-9.+-]{0,63}))?$/;

export interface ExtensionReference {
  publisher: string;
  name: string;
  version: string | undefined;
}

export interface ExtensionMatch {
  ioc: FeedIOC;
  registry: ExtensionRegistry;
}

/**
 * Check if a file can declare VS Code extensions.
 */
export function isExtensionReferenceFile(relativePath: string): boolean {
  const parts = relativePath.replace(/\\/g, "/").split("/");
  const basename = parts[parts.length - 1] ?? "";
  if (basename === "extensions.json") return parts[parts.length - 2] === ".vscode";
  if (basename.toLowerCase().endsWith(".code-workspace")) return true;
  return basename === "devcontainer.json" || basename === ".devcontainer.json" || basename === "package.json";
}

/**
 * Match one extension identity against the feed, first registry wins.
 */
export function matchExtensionIOC(
  publisher: string,
  name: string,
  version: string | undefined,
  registries: readonly ExtensionRegistry[],
  feed: FeedIOC[],
): ExtensionMatch | null {
  for (const registry of registries) {
    const ioc = matchPackageIOC(FEED_PREFIX[registry], `${publisher}.${name}`, version, feed);
    if (ioc) return { ioc, registry };
  }
  return null;
}

function parseReference(raw: unknown, version?: unknown): ExtensionReference | null {
  if (typeof raw !== "string") return null;
  const m = EXTENSION_ID.exec(raw.trim());
  if (!m) return null;
  const pinned = m[3] ?? (typeof version === "string" && version.length > 0 ? version : undefined);
  return { publisher: m[1]!, name: m[2]!, version: pinned };
}

function stringList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Extract every extension a file declares, installs or packages.
 */
export function extractExtensionReferences(
  content: string,
  relativePath: string,
): ExtensionReference[] {
  let doc: unknown;
  try {
    doc = JSON.parse(stripJsonc(content.replace(/^\uFEFF/, "")));
  } catch {
    return [];
  }
  if (!isJsonObject(doc)) return [];

  const basename = relativePath.replace(/\\/g, "/").split("/").pop() ?? "";
  const refs: (ExtensionReference | null)[] = [];

  if (basename === "extensions.json") {
    for (const id of stringList(doc.recommendations)) refs.push(parseReference(id));
  } else if (basename.toLowerCase().endsWith(".code-workspace")) {
    // A multi-root workspace file carries the same recommendations list under
    // "extensions", and VS Code prompts for it the same way (6.3.0 pre-release
    // review).
    const extensions = isJsonObject(doc.extensions) ? doc.extensions : {};
    for (const id of stringList(extensions.recommendations)) refs.push(parseReference(id));
  } else if (basename === "devcontainer.json" || basename === ".devcontainer.json") {
    const customizations = isJsonObject(doc.customizations) ? doc.customizations : {};
    const vscode = isJsonObject(customizations.vscode) ? customizations.vscode : {};
    for (const id of stringList(vscode.extensions)) refs.push(parseReference(id));
    for (const id of stringList(doc.extensions)) refs.push(parseReference(id));
  } else if (basename === "package.json") {
    const engines = isJsonObject(doc.engines) ? doc.engines : {};
    if (typeof doc.publisher === "string" && typeof engines.vscode === "string" && typeof doc.name === "string") {
      refs.push(parseReference(`${doc.publisher}.${doc.name}`, doc.version));
    }
  }

  return refs.filter((r): r is ExtensionReference => r !== null);
}

/**
 * Build the finding for a matched extension.
 */
export function extensionFinding(
  ref: ExtensionReference,
  match: ExtensionMatch,
  relativePath: string,
): Finding {
  const id = `${ref.publisher}.${ref.name}`;
  const { ioc, registry } = match;
  return {
    rule: "VSCODE_MALICIOUS_EXTENSION",
    description: `Known malicious ${REGISTRY_LABEL[registry]} extension: ${id}${ref.version ? `@${ref.version}` : ""}${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
    severity: ioc.severity,
    file: relativePath,
    match: ref.version ? `${id}@${ref.version}` : id,
    confidence: ioc.confidence,
    category: "malware",
    recommendation: `Uninstall ${id} from every editor profile, remove it from recommendations and devcontainer `
      + "configuration, and rotate credentials available to the editor (tokens, SSH keys, cloud CLIs). "
      + "This extension is listed in threat intelligence feeds.",
  };
}

/**
 * Scan a file for declared, installed or packaged extensions matching the feed.
 */
export function scanExtensionReferences(
  content: string,
  relativePath: string,
  feed?: FeedIOC[],
): Finding[] {
  const iocFeed = feed ?? loadThreatIntel();
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const ref of extractExtensionReferences(content, relativePath)) {
    const key = `${ref.publisher}.${ref.name}@${ref.version ?? ""}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const match = matchExtensionIOC(ref.publisher, ref.name, ref.version, BOTH_REGISTRIES, iocFeed);
    if (!match) continue;
    const finding = extensionFinding(ref, match, relativePath);
    // A recommendation, devcontainer entry or manifest does not say which
    // registry installs it, and the same id can belong to different publishers
    // on each. A hit that exists only in the Open VSX namespace is therefore
    // real for VSCodium / Cursor / Open VSX users and possibly someone else's
    // extension for Marketplace users: reported, but at medium and saying so.
    if (match.registry === "openvsx") {
      finding.severity = "medium";
      finding.description +=
        " Listed for Open VSX only: this applies if the workspace is opened in an editor that installs from Open VSX (VSCodium, Cursor, Gitpod and other VS Code forks); on the VS Code Marketplace the same id may belong to a different publisher.";
    }
    findings.push(finding);
  }
  return findings;
}
