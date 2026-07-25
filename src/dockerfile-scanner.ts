/**
 * Dockerfile and container configuration scanner.
 *
 * Detects supply-chain risks in Dockerfile, docker-compose.yml, and
 * related container configuration files.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";
import { isPatternMatchAccepted } from "./patterns.js";

// ---------------------------------------------------------------------------
// Global npm install: pinned or not?
// ---------------------------------------------------------------------------

/** npm flags that carry no package name. */
const NPM_FLAG_RE = /^-/;

/** Shell operators that end the npm command (`&& npm cache clean --force`). */
const SHELL_SEPARATOR_RE = /^(?:&&|\|\||;|\||&|\\)$/;

/**
 * A local artifact rather than a registry package: a path, a packed tarball, or
 * an explicit `file:` specifier. Installing your own build output globally is
 * not the mutable-registry-dependency this rule is about.
 */
const LOCAL_ARTIFACT_RE = /^(?:file:|\.{0,2}[\\/]|[A-Za-z]:[\\/])|\.(?:tgz|tar\.gz)$/;

/**
 * An EXACT version selector: `9`, `11.18.0`, `1.2.3-rc.1`, or a `@scope/name`
 * spec ending in one. Range operators (`^`, `~`, `>`, `*`, `x`) and dist-tags
 * (`latest`, `next`, `beta`) are NOT exact - both can resolve to a different
 * package on the next build, which is exactly what this rule warns about.
 */
function isPinnedSpec(spec: string): boolean {
  if (LOCAL_ARTIFACT_RE.test(spec)) return true;
  // Ignore a leading scope "@" so @scope/name@1.2.3 splits on the right "@".
  const at = spec.lastIndexOf("@");
  if (at <= 0) return false; // no version at all: `npm i -g pnpm`
  const version = spec.slice(at + 1);
  return /^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$/.test(version);
}

/**
 * True when a global npm install leaves at least one package UNPINNED.
 *
 * The rule's own recommendation has always been "pin the global package
 * version", yet the pattern fired on `RUN npm install -g pnpm@9` and
 * `RUN npm install -g npm@11.18.0` - installs that already do exactly what the
 * recommendation asks (27 such findings in one Elvatis repo alone). Matching
 * the command shape says nothing about the risk; the package SPECS do.
 */
export function isUnpinnedGlobalInstall(specs: string): boolean {
  const tokens = specs
    .trim()
    .split(/\s+/)
    .filter((t) => t !== "");

  const packages: string[] = [];
  for (const token of tokens) {
    if (SHELL_SEPARATOR_RE.test(token)) break; // rest belongs to another command
    if (NPM_FLAG_RE.test(token)) continue;
    packages.push(token);
  }

  // No parseable package spec (e.g. a shell variable): keep reporting.
  if (packages.length === 0) return true;
  return packages.some((p) => !isPinnedSpec(p));
}

// ---------------------------------------------------------------------------
// Dockerfile patterns
// ---------------------------------------------------------------------------

export const DOCKERFILE_PATTERNS: PatternEntry[] = [
  {
    name: "docker-curl-pipe",
    pattern:
      "RUN\\s+.*(?:curl|wget)\\s+[^|]*\\|\\s*(?:bash|sh|python|node|perl)",
    description:
      "Dockerfile downloads and pipes remote content to a shell (remote code execution risk)",
    severity: "critical",
    rule: "DOCKER_CURL_PIPE",
  },
  {
    name: "docker-unpinned-base",
    pattern:
      "FROM\\s+(?!scratch)\\S+:(?:latest|stable|lts|current|mainline)(?:\\s|$)",
    description:
      "Dockerfile uses a mutable tag (e.g. :latest) instead of a pinned digest. The image can change without notice.",
    severity: "high",
    rule: "DOCKER_UNPINNED_BASE",
  },
  {
    name: "docker-no-tag",
    pattern:
      "FROM\\s+(?!scratch)[a-z][a-z0-9._/-]*\\s*$",
    description:
      "Dockerfile FROM without a tag or digest. Defaults to :latest, which is mutable.",
    severity: "high",
    rule: "DOCKER_NO_TAG",
  },
  {
    name: "docker-http-source",
    pattern:
      "(?:ADD|COPY)\\s+https?://",
    description:
      "Dockerfile downloads files via ADD/COPY from an HTTP(S) URL without checksum verification",
    severity: "high",
    rule: "DOCKER_HTTP_SOURCE",
  },
  {
    name: "docker-secrets-build",
    pattern:
      "(?:ENV|ARG)\\s+\\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS|AUTH)\\w*\\s*=\\s*\\S+",
    description:
      "Hardcoded secret in Dockerfile ENV/ARG. Secrets leak into image layers and history.",
    severity: "high",
    rule: "DOCKER_SECRETS_BUILD",
  },
  {
    name: "docker-npm-global",
    // Group 1 is everything after the global flag; isUnpinnedGlobalInstall()
    // decides whether those package specs are actually unpinned (v5.18).
    pattern:
      "RUN\\s+npm\\s+(?:install|i|add)\\s+(?:-g|--global|--location=global)\\s+(.+)$",
    description:
      "Unpinned global npm install in Dockerfile. Without a version the image installs " +
      "whatever the registry serves at build time, so the same Dockerfile can produce a " +
      "different (or compromised) package on the next build.",
    severity: "medium",
    rule: "DOCKER_NPM_GLOBAL",
    valueFilter: isUnpinnedGlobalInstall,
  },
  {
    name: "docker-untrusted-registry",
    pattern:
      "FROM\\s+(?!(?:docker\\.io|ghcr\\.io|gcr\\.io|mcr\\.microsoft\\.com|public\\.ecr\\.aws|quay\\.io|registry\\.access\\.redhat\\.com|scratch))[a-z0-9]+\\.[a-z]{2,}/",
    description:
      "Dockerfile pulls a base image from a non-standard container registry",
    severity: "medium",
    rule: "DOCKER_UNTRUSTED_REGISTRY",
  },
  {
    name: "docker-run-chmod-suid",
    pattern:
      "RUN\\s+.*chmod\\s+[ugo]*\\+s",
    description:
      "Dockerfile sets SUID/SGID bit on a file. This can be used for privilege escalation.",
    severity: "high",
    rule: "DOCKER_SUID",
  },
  {
    name: "docker-apt-no-verify",
    pattern:
      "RUN\\s+.*apt(?:-get)?\\s+.*--allow-unauthenticated|--force-yes",
    description:
      "Dockerfile disables APT package signature verification. Packages may be tampered with.",
    severity: "high",
    rule: "DOCKER_APT_NO_VERIFY",
  },
];

/** Files that this scanner checks */
const DOCKER_FILE_PATTERNS = [
  /^Dockerfile$/i,
  /^Dockerfile\..+$/i,
  /^docker-compose\.ya?ml$/i,
  /^\.dockerignore$/i,
  /^Containerfile$/i,
];

/**
 * Check whether a filename is a Docker-related file.
 */
export function isDockerFile(filename: string): boolean {
  return DOCKER_FILE_PATTERNS.some((re) => re.test(filename));
}

/**
 * Scan a single Docker-related file for supply-chain risks.
 */
export function scanDockerFile(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (const pattern of DOCKERFILE_PATTERNS) {
    const regex = new RegExp(pattern.pattern, "i");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = regex.exec(line);
      if (match) {
        regex.lastIndex = 0;
        // v5.18: value-level guard (see PatternEntry.valueFilter)
        if (!isPatternMatchAccepted(pattern, match)) continue;
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match: match[0].length > 120 ? match[0].substring(0, 120) + "..." : match[0],
          recommendation: getDockerRecommendation(pattern.rule),
        });
      }
    }
  }

  return findings;
}

/**
 * Scan a directory for all Docker-related files.
 */
export function scanDockerFiles(dir: string): Finding[] {
  const findings: Finding[] = [];

  // Check root-level Docker files
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!isDockerFile(entry.name)) continue;

      const fullPath = path.join(dir, entry.name);
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        findings.push(...scanDockerFile(content, entry.name));
      } catch {
        // skip unreadable files
      }
    }
  } catch {
    // directory not readable
  }

  return findings;
}

function getDockerRecommendation(rule: string): string {
  const map: Record<string, string> = {
    DOCKER_CURL_PIPE:
      "Download files to disk first, verify their checksum, then execute. Never pipe remote content to a shell.",
    DOCKER_UNPINNED_BASE:
      "Pin base images by digest: FROM node:20@sha256:abc... This ensures reproducible builds.",
    DOCKER_NO_TAG:
      "Always specify a tag or digest for base images. Using no tag defaults to :latest which is mutable.",
    DOCKER_HTTP_SOURCE:
      "Download files in a RUN step with checksum verification instead of using ADD with URLs.",
    DOCKER_SECRETS_BUILD:
      "Use Docker BuildKit secrets (--mount=type=secret) or runtime environment variables instead of hardcoding secrets.",
    DOCKER_NPM_GLOBAL:
      "Pin every globally installed package to an exact version (npm install -g pnpm@9.15.0), " +
      "or install locally with npx. A bare name, a dist-tag (@latest) and a range (@^9) all resolve " +
      "at build time, so the image is not reproducible and a hijacked release lands silently.",
    DOCKER_UNTRUSTED_REGISTRY:
      "Use images from trusted registries (Docker Hub, GHCR, GCR, ECR) or verify the registry's authenticity.",
    DOCKER_SUID:
      "Avoid setting SUID/SGID bits in containers. Use capabilities or non-root users instead.",
    DOCKER_APT_NO_VERIFY:
      "Never disable APT signature verification. Fix GPG key issues instead.",
  };
  return map[rule] ?? "Review this Dockerfile instruction manually.";
}
