/**
 * Content-addressed trust for supply-chain-guard's own inert IOC definitions.
 *
 * A target controls its directory name, package metadata and Git configuration,
 * so none of those values may grant a scanner exemption. Unchanged source files
 * are recognised only by an exact path plus a SHA-256 digest from the manifest
 * shipped with the running scanner. Source CRLF is canonicalised to LF so the
 * same checkout is recognised across platforms. Compiled files must byte-match
 * the running installation. Any content edit fails closed to the normal scan.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import inertFilePaths from "./self-scan-files.json";

interface SelfScanManifest {
  schemaVersion: number;
  algorithm: string;
  files: Record<string, string>;
}

export const SELF_SCAN_INERT_FILES: ReadonlySet<string> = new Set(inertFilePaths);

export const SELF_SCAN_INERT_COMPILED_FILES: ReadonlySet<string> = new Set(
  inertFilePaths
    .filter(
      (relativePath) =>
        relativePath.startsWith("src/") &&
        !relativePath.startsWith("src/__tests__/") &&
        relativePath.endsWith(".ts"),
    )
    .flatMap((relativePath) => {
      const modulePath = relativePath.slice("src/".length, -".ts".length);
      return [`dist/${modulePath}.js`, `dist/${modulePath}.d.ts`];
    }),
);

export function isSelfScanInertFile(relativePath: string): boolean {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  return (
    SELF_SCAN_INERT_FILES.has(normalizedPath) ||
    SELF_SCAN_INERT_COMPILED_FILES.has(normalizedPath)
  );
}

const SCANNER_PACKAGE_ROOT = fs.realpathSync(path.resolve(__dirname, ".."));
const SHA256_RE = /^[a-f0-9]{64}$/;

function loadSourceDigests(): ReadonlyMap<string, string> {
  try {
    const manifestPath = path.join(SCANNER_PACKAGE_ROOT, "self-scan-manifest.json");
    const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as SelfScanManifest;
    if (
      parsed.schemaVersion !== 1 ||
      parsed.algorithm !== "sha256" ||
      !parsed.files ||
      typeof parsed.files !== "object"
    ) {
      return new Map();
    }

    const entries = Object.entries(parsed.files).filter(
      ([relativePath, digest]) =>
        SELF_SCAN_INERT_FILES.has(relativePath) &&
        typeof digest === "string" &&
        SHA256_RE.test(digest),
    );
    return new Map(entries);
  } catch {
    return new Map();
  }
}

const SOURCE_DIGESTS = loadSourceDigests();
const compiledDigestCache = new Map<string, string | null>();

function sha256(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function sha256Source(content: Buffer): string {
  return createHash("sha256")
    .update(content.toString("utf8").replaceAll("\r\n", "\n"), "utf8")
    .digest("hex");
}

function installedCompiledDigest(relativePath: string): string | null {
  const cached = compiledDigestCache.get(relativePath);
  if (cached !== undefined) return cached;

  try {
    const installedPath = path.join(
      SCANNER_PACKAGE_ROOT,
      ...relativePath.split("/"),
    );
    const digest = sha256(fs.readFileSync(installedPath));
    compiledDigestCache.set(relativePath, digest);
    return digest;
  } catch {
    compiledDigestCache.set(relativePath, null);
    return null;
  }
}

/**
 * Whether one target file is content-identical to a reviewed inert file
 * shipped by this scanner. This grants no repository-wide trust.
 */
export function isVerifiedSelfScanFile(
  relativePath: string,
  content: Buffer,
): boolean {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  if (SELF_SCAN_INERT_FILES.has(normalizedPath)) {
    return SOURCE_DIGESTS.get(normalizedPath) === sha256Source(content);
  }
  if (SELF_SCAN_INERT_COMPILED_FILES.has(normalizedPath)) {
    return installedCompiledDigest(normalizedPath) === sha256(content);
  }
  return false;
}
