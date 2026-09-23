/**
 * Container image identity matching.
 *
 * Matches the images a project builds from or runs against `docker:` feed
 * entries: `docker:<name>@<tag>` or `docker:<name>@sha256:<digest>`.
 *
 * Where images are referenced:
 *   - Dockerfile / Containerfile: `FROM` (with `--platform`, `AS`) and
 *     `COPY --from=<image>`; build-stage names are not images and are skipped
 *   - any YAML (compose, Kubernetes, workflow `container:` / `services:`):
 *     `image:` values, plus `docker://<image>` in workflow `uses:`
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
    const expand = (value: string): string =>
      value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
        (whole, braced: string | undefined, fallback: string | undefined, bare: string | undefined) => {
          const name = braced ?? bare!;
          return globalArgs.get(name) ?? fallback ?? whole;
        });
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
      const copy = /^COPY\s+(?:--\S+\s+)*--from=(\S+)/i.exec(line);
      if (copy && !stages.has(copy[1]!.toLowerCase()) && /[/:@]/.test(copy[1]!) && parseImageReference(copy[1]!)) {
        out.push({ raw: copy[1]!, line: i + 1 });
      }
    });
    return out;
  }
  lines.forEach((raw, i) => {
    const text = raw.replace(/\s+#.*$/, "");
    // `image: <ref>` anywhere, and a workflow's string-form `container: <ref>`
    // (the map form is `container:` followed by an `image:` line).
    const image = /^\s*-?\s*(?:image|container):\s*(\S.*)$/.exec(text);
    if (image) {
      const value = unquote(image[1]!);
      if (parseImageReference(value)) out.push({ raw: value, line: i + 1 });
      return;
    }
    for (const m of text.matchAll(/docker:\/\/([^\s"'#]+)/g)) {
      if (parseImageReference(m[1]!)) out.push({ raw: m[1]!, line: i + 1 });
    }
  });
  return out;
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
