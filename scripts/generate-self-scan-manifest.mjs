// Generate or verify the deterministic manifest used to recognise unchanged
// supply-chain-guard source files during a local checkout scan.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const pathsFile = join(repoRoot, "src", "self-scan-files.json");
const manifestFile = join(repoRoot, "self-scan-manifest.json");

function canonicalSourceContent(content) {
  return content.replaceAll("\r\n", "\n");
}

export function buildSelfScanManifest(root = repoRoot) {
  const paths = JSON.parse(readFileSync(join(root, "src", "self-scan-files.json"), "utf8"));
  if (!Array.isArray(paths) || paths.some((entry) => typeof entry !== "string")) {
    throw new Error("src/self-scan-files.json must contain an array of paths");
  }

  const files = {};
  for (const relativePath of [...paths].sort()) {
    const normalized = relativePath.replaceAll("\\", "/");
    if (!normalized.startsWith("src/") || normalized.includes("../")) {
      throw new Error(`Unsafe self-scan manifest path: ${relativePath}`);
    }
    const absolutePath = join(root, ...normalized.split("/"));
    if (!existsSync(absolutePath)) {
      throw new Error(`Self-scan manifest path does not exist: ${relativePath}`);
    }
    files[normalized] = createHash("sha256")
      .update(canonicalSourceContent(readFileSync(absolutePath, "utf8")), "utf8")
      .digest("hex");
  }

  return { schemaVersion: 1, algorithm: "sha256", files };
}

export function serializeSelfScanManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

const isMain =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const expected = serializeSelfScanManifest(buildSelfScanManifest());
  if (process.argv.includes("--check")) {
    const current = existsSync(manifestFile) ? readFileSync(manifestFile, "utf8") : "";
    if (current.replaceAll("\r", "") !== expected.replaceAll("\r", "")) {
      console.error(
        "self-scan-manifest.json is stale; run `npm run self-scan:generate` and commit it.",
      );
      process.exitCode = 1;
    }
  } else {
    writeFileSync(manifestFile, expected, "utf8");
    console.log(`Wrote ${manifestFile}`);
  }
}
