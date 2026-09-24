/**
 * Container image identity matching.
 *
 * Matches the images a project builds from or runs against `docker:` feed
 * entries: `docker:<name>@<tag>` or `docker:<name>@sha256:<digest>`.
 *
 * Where images are referenced:
 *   - Dockerfile / Containerfile: `FROM` (with `--platform`, `AS`),
 *     `COPY --from=<image>` and `RUN --mount=...,from=<image>`, all with global
 *     ARGs expanded; build-stage names are not images and are skipped
 *   - any YAML (compose, Kubernetes, workflow `container:` / `services:`):
 *     `image:` values, plus `docker://<image>` in workflow `uses:`
 *   - `image:` as a map: GitLab CI `name:`, and Helm-values `registry:` /
 *     `repository:` with `tag:` / `digest:` (block or one-line flow form)
 *   - GitLab CI `services:` as a list: bare image items and `name:` maps
 *
 * A DIGEST names content, so it is matched whatever repository name carries
 * it: the same manifest pulled through a mirror or re-pushed under another
 * name is the same image. A TAG is matched only for its repository, and the
 * feed carries tags only where the tag never pointed at clean content.
 *
 * Names are normalised the way Docker resolves them: `docker.io/`,
 * `index.docker.io/` and `registry-1.docker.io/` are dropped, a bare name is an
 * official image under `library/`, and any other registry host stays part of
 * the name, since `ghcr.io/x/y` and `x/y` are different images.
 */

import type { Finding } from "./types.js";
import { loadThreatIntel, matchPackageIOC, type FeedIOC } from "./threat-intel.js";
import { stripHashComment, trimTrailing } from "./text-lines.js";

export interface ImageReference {
  name: string;
  tag: string | undefined;
  digest: string | undefined;
}

export interface LocatedImageReference {
  raw: string;
  line: number;
}

const DOCKER_HUB_HOSTS = new Set(["docker.io", "index.docker.io", "registry-1.docker.io"]);
/** Path component: lowercase alphanumerics with . _ - separators. */
const COMPONENT = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
const TAG = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * Parse an image reference, or return null for anything that is not one
 * (a variable, `scratch`, a malformed name).
 */
export function parseImageReference(raw: string): ImageReference | null {
  // No separate check for variables or whitespace: "$", "{" and " " are
  // outside the component, tag and digest grammars, so such a value fails below.
  let ref = raw.trim();
  if (!ref) return null;

  let digest: string | undefined;
  const at = ref.indexOf("@");
  if (at >= 0) {
    digest = ref.slice(at + 1).toLowerCase();
    if (!DIGEST.test(digest)) return null;
    ref = ref.slice(0, at);
  }

  let tag: string | undefined;
  const lastSlash = ref.lastIndexOf("/");
  const colon = ref.lastIndexOf(":");
  if (colon > lastSlash) {
    tag = ref.slice(colon + 1);
    ref = ref.slice(0, colon);
    if (!TAG.test(tag)) return null;
  }

  const parts = ref.toLowerCase().split("/");
  let host: string | undefined;
  if (parts.length > 1 && (parts[0]!.includes(".") || parts[0]!.includes(":") || parts[0] === "localhost")) {
    host = parts.shift();
  }
  if (parts.length === 0 || !parts.every((p) => COMPONENT.test(p))) return null;
  if (host && DOCKER_HUB_HOSTS.has(host)) host = undefined;
  if (!host && parts.length === 1) {
    if (parts[0] === "scratch") return null;
    parts.unshift("library");
  }
  const name = host ? `${host}/${parts.join("/")}` : parts.join("/");
  return { name, tag, digest };
}

function isYaml(relativePath: string): boolean {
  return /\.ya?ml$/i.test(relativePath);
}

function basenameOf(relativePath: string): string {
  return relativePath.replace(/\\/g, "/").split("/").pop() ?? "";
}

/** Dockerfile-syntax files (not compose, which is YAML). */
export function isDockerfileSyntax(relativePath: string): boolean {
  const b = basenameOf(relativePath);
  return /^(?:Dockerfile|Containerfile)(?:\..+)?$/i.test(b) && !isYaml(b);
}

/**
 * Check if a file can reference container images.
 */
export function isImageReferenceFile(relativePath: string): boolean {
  return isDockerfileSyntax(relativePath) || isYaml(relativePath);
}

function unquote(value: string): string {
  const m = /^(["'])(.*)\1$/.exec(value.trim());
  return m ? m[2]! : value.trim();
}

/**
 * Extract image references with their lines.
 */
export function extractImageReferences(content: string, relativePath: string): LocatedImageReference[] {
  const out: LocatedImageReference[] = [];
  const lines = content.split(/\r?\n/);
  if (isDockerfileSyntax(relativePath)) {
    const stages = new Set<string>();
    // Global ARG defaults: only ARGs declared before the first FROM are in
    // scope for FROM lines, exactly as Docker resolves them.
    const globalArgs = new Map<string, string>();
    let seenFrom = false;
    // An image reference is far shorter than this. Expanding `$A$A$A...` with a
    // long A could otherwise build a string V8 cannot hold and end the scan; a
    // value that would grow past the cap stays unexpanded and fails the grammar.
    const MAX_EXPANDED = 4096;
    const expand = (value: string): string => {
      if (value.length > MAX_EXPANDED) return value;
      let total = value.length;
      let over = false;
      const expanded = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
        (whole, braced: string | undefined, fallback: string | undefined, bare: string | undefined) => {
          const name = braced ?? bare!;
          const replacement = globalArgs.get(name) ?? fallback ?? whole;
          total += replacement.length;
          if (total > MAX_EXPANDED) over = true;
          return over ? whole : replacement;
        });
      return over ? value : expanded;
    };
    lines.forEach((raw, i) => {
      // Both instructions are anchored at the line start, so a "# FROM ..."
      // comment never matches.
      const line = raw.trim();
      const arg = /^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)/i.exec(line);
      if (arg && !seenFrom) globalArgs.set(arg[1]!, arg[2]!.replace(/^(["'])(.*)\1$/, "$2"));
      const from = /^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
      if (from) seenFrom = true;
      if (from) {
        // An unresolved variable stays in place and fails the reference grammar.
        const image = expand(from[1]!);
        if (!stages.has(image.toLowerCase()) && parseImageReference(image)) out.push({ raw: image, line: i + 1 });
        if (from[2]) stages.add(from[2].toLowerCase());
        return;
      }
      // An image named by COPY --from or by from= in a RUN --mount; a bare
      // word there is a build stage (or a stage index), never pulled.
      const pushSource = (value: string) => {
        const image = expand(value);
        if (!stages.has(image.toLowerCase()) && /[/:@]/.test(image) && parseImageReference(image)) {
          out.push({ raw: image, line: i + 1 });
        }
      };
      const copy = /^COPY\s+(?:--\S+\s+)*--from=(\S+)/i.exec(line);
      if (copy) pushSource(copy[1]!);
      if (/^RUN\s/i.test(line)) {
        for (const mount of line.matchAll(/--mount=(\S+)/g)) {
          const from = mount[1]!.split(",").find((opt) => opt.startsWith("from="));
          if (from) pushSource(from.slice("from=".length));
        }
      }
    });
    return out;
  }
  // `image:` in map form: GitLab CI `name:`, or Helm-values `registry:` /
  // `repository:` / `tag:` / `digest:`. Only the image key's own direct
  // children are paired, never siblings or deeper keys.
  let block: { indent: number; childIndent: number | undefined; fields: Map<string, { value: string; line: number }> } | undefined;
  const flush = () => {
    if (block) pushImageMap(block.fields, out);
    block = undefined;
  };
  // GitLab CI `services:` whose value is a LIST: items are a bare image or a
  // map with `name:`. Compose and GitHub Actions `services:` are maps of
  // service name -> {image: ...}, read by the image: path; their first child
  // is not a list item, so this state is dropped on it and adds nothing.
  let services: { keyIndent: number; itemIndent: number | undefined; contentIndent: number | undefined; named: boolean } | undefined;
  const serviceEntry = (content: string, line: number) => {
    if (content.startsWith("{") && content.endsWith("}")) {
      const name = parseFlowMap(content, line).get("name");
      if (name && parseImageReference(name.value)) out.push({ raw: name.value, line });
      return;
    }
    // `key: value` needs whitespace (or the end) after the colon, which an
    // image reference such as postgres:16 never has.
    const kv = /^([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]+(.*))?$/.exec(content);
    if (kv) {
      const value = unquote(kv[2] ?? "");
      if (kv[1] === "name" && value && services) {
        services.named = true;
        if (parseImageReference(value)) out.push({ raw: value, line });
      }
      return;
    }
    const value = unquote(content);
    if (parseImageReference(value)) out.push({ raw: value, line });
  };
  lines.forEach((raw, i) => {
    const text = stripHashComment(raw);
    const trimmed = text.trimStart();
    if (services && trimmed && !trimmed.startsWith("#")) {
      const indent = text.length - trimmed.length;
      const isItem = trimmed === "-" || trimmed.startsWith("- ");
      if (services.itemIndent === undefined) {
        // A compact list may sit at the key's own indentation.
        if (isItem && indent >= services.keyIndent) services.itemIndent = indent;
        else services = undefined;
      }
      if (services && indent === services.itemIndent && isItem) {
        const content = trimmed.slice(1).trimStart();
        services.contentIndent = content ? indent + trimmed.length - content.length : undefined;
        services.named = false;
        if (content.startsWith("{") && !content.endsWith("}")) {
          // A flow-map item continued on the next lines (`- {name: x,` then
          // `alias: y}`): joined back into one map, at most 16 lines ahead.
          // The continuation lines are then part of an item already read.
          let entry = content;
          for (let j = i + 1; j < lines.length && j <= i + 16; j++) {
            const next = stripHashComment(lines[j] ?? "").trim();
            entry += ` ${next}`;
            if (next.endsWith("}")) break;
          }
          if (entry.endsWith("}")) serviceEntry(entry, i + 1);
          services.named = true;
        } else if (content) serviceEntry(content, i + 1);
      } else if (services && indent > services.itemIndent!) {
        // `- alias: x` then `name: y`: a key at the item's own content column.
        services.contentIndent ??= indent;
        if (indent === services.contentIndent && !services.named) serviceEntry(trimmed, i + 1);
      } else {
        services = undefined;
      }
    }
    const servicesKey = /^([ \t]*)services:[ \t]*(.*)$/.exec(text);
    if (servicesKey) {
      const value = servicesKey[2]!;
      if (!value) {
        services = { keyIndent: servicesKey[1]!.length, itemIndent: undefined, contentIndent: undefined, named: false };
      } else if (value.startsWith("[") && value.endsWith("]") && !value.includes("{")) {
        // One-line flow list of bare images.
        for (const item of value.slice(1, -1).split(",")) {
          const ref = unquote(item);
          if (parseImageReference(ref)) out.push({ raw: ref, line: i + 1 });
        }
      }
    }
    if (block) {
      if (!trimmed || trimmed.startsWith("#")) return;
      const indent = text.length - trimmed.length;
      if (indent > block.indent) {
        block.childIndent ??= indent;
        const kv = indent === block.childIndent ? /^([A-Za-z_]+):\s*(.*)$/.exec(trimmed) : null;
        if (kv && !block.fields.has(kv[1]!)) block.fields.set(kv[1]!, { value: unquote(kv[2]!), line: i + 1 });
        return;
      }
      flush();
    }
    // `image: <ref>` anywhere, and a workflow's string-form `container: <ref>`
    // (the map form is `container:` followed by an `image:` line).
    // Written as [ \t]*(?:-[ \t]*)? because \s*-?\s* is quadratic on a long
    // run of whitespace (both \s* can split the same run every way).
    const image = /^([ \t]*(?:-[ \t]*)?)(image|container):[ \t]*(\S.*)$/.exec(text);
    if (image) {
      const value = unquote(image[3]!);
      if (value.startsWith("{") && value.endsWith("}") && image[2] === "image") {
        pushImageMap(parseFlowMap(value, i + 1), out);
      } else if (parseImageReference(value)) {
        out.push({ raw: value, line: i + 1 });
      }
      return;
    }
    const opener = /^([ \t]*(?:-[ \t]*)?)image:[ \t]*$/.exec(text);
    if (opener) {
      block = { indent: opener[1]!.length, childIndent: undefined, fields: new Map() };
      return;
    }
    for (const m of text.matchAll(/docker:\/\/([^\s"'#]+)/g)) {
      if (parseImageReference(m[1]!)) out.push({ raw: m[1]!, line: i + 1 });
    }
  });
  flush();
  return out;
}

type ImageMap = Map<string, { value: string; line: number }>;

/** `{a: b, c: "d"}` on one line; nested values are kept as text, not parsed. */
function parseFlowMap(value: string, line: number): ImageMap {
  const fields: ImageMap = new Map();
  for (const part of value.slice(1, -1).split(",")) {
    const colon = part.indexOf(":");
    if (colon < 0) continue;
    const key = part.slice(0, colon).trim();
    if (!fields.has(key)) fields.set(key, { value: unquote(part.slice(colon + 1)), line });
  }
  return fields;
}

/** Turn the direct children of one `image:` key into a reference. */
function pushImageMap(fields: ImageMap, out: LocatedImageReference[]): void {
  const name = fields.get("name");
  if (name) {
    if (parseImageReference(name.value)) out.push({ raw: name.value, line: name.line });
    return;
  }
  const repository = fields.get("repository");
  if (!repository?.value) return;
  const registry = fields.get("registry")?.value;
  const tag = fields.get("tag")?.value;
  const digest = fields.get("digest")?.value;
  const raw = `${registry ? `${trimTrailing(registry, "/")}/` : ""}${repository.value}`
    + `${tag ? `:${tag}` : ""}${digest ? `@${digest}` : ""}`;
  if (parseImageReference(raw)) out.push({ raw, line: repository.line });
}

const digestIndexCache = new WeakMap<FeedIOC[], Map<string, FeedIOC>>();

/** docker: entries keyed by digest alone (see the file header). */
function digestIndex(feed: FeedIOC[]): Map<string, FeedIOC> {
  const cached = digestIndexCache.get(feed);
  if (cached) return cached;
  const index = new Map<string, FeedIOC>();
  for (const ioc of feed) {
    if (ioc.type !== "package" || !ioc.value.startsWith("docker:")) continue;
    const at = ioc.value.lastIndexOf("@");
    const version = at > 0 ? ioc.value.slice(at + 1).toLowerCase() : "";
    if (DIGEST.test(version) && !index.has(version)) index.set(version, ioc);
  }
  digestIndexCache.set(feed, index);
  return index;
}

/**
 * Scan a Dockerfile or YAML file for images matching `docker:` feed IOCs.
 */
export function scanImageReferences(content: string, relativePath: string, feed?: FeedIOC[]): Finding[] {
  const iocFeed = feed ?? loadThreatIntel();
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const { raw, line } of extractImageReferences(content, relativePath)) {
    const ref = parseImageReference(raw);
    if (!ref) continue;
    const key = `${ref.name}:${ref.tag ?? ""}@${ref.digest ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const ioc =
      (ref.digest ? digestIndex(iocFeed).get(ref.digest) : undefined) ??
      (ref.tag ? matchPackageIOC("docker", ref.name, ref.tag, iocFeed) : null);
    if (!ioc) continue;
    findings.push({
      rule: "DOCKER_MALICIOUS_IMAGE",
      description: `Known malicious container image: ${raw} (${ioc.value.slice("docker:".length)})${ioc.family ? ` (${ioc.family})` : ""}${ioc.campaign ? ` - ${ioc.campaign}` : ""}`,
      severity: ioc.severity,
      file: relativePath,
      line,
      match: raw.length > 120 ? `${raw.slice(0, 120)}...` : raw,
      confidence: ioc.confidence,
      category: "malware",
      recommendation: "Stop using this image, remove it from local and CI image caches (docker image rm, runner caches), "
        + "pin a verified clean digest instead, and rotate credentials available to containers that ran it. "
        + "This image is listed in threat intelligence feeds.",
    });
  }
  return findings;
}
