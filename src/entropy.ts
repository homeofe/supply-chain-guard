/**
 * Shannon entropy analysis for detecting obfuscated/encoded payloads.
 *
 * High entropy in a source file indicates compressed, encoded or obfuscated
 * content, a common technique in supply-chain malware.
 *
 * Entropy is computed over UTF-8 BYTES, which bounds it to 0..8. It used to be
 * computed over CODE POINTS, which is unbounded: a file with many distinct
 * non-Latin characters could exceed 8 and trip a threshold that was documented
 * as being on the 0..8 scale.
 */

import type { Finding } from "./types.js";

/**
 * Shannon entropy over UTF-8 bytes. Returns 0 (uniform) to 8 (random).
 *
 * Byte-based on purpose. Iterating a JS string yields CODE POINTS, of which
 * there are ~1.1 million, so the result is unbounded and text in a non-Latin
 * script scores higher purely for having a larger alphabet. For pure ASCII the
 * two are identical, so this changes nothing for the overwhelming majority of
 * scanned files while making the value mean what the thresholds assume.
 */
export function shannonEntropy(data: string): number {
  if (data.length === 0) return 0;

  const bytes = Buffer.from(data, "utf8");
  const freq = new Array<number>(256).fill(0);
  for (const b of bytes) freq[b]++;

  let entropy = 0;
  const len = bytes.length;
  for (const count of freq) {
    if (count === 0) continue;
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * File-level threshold, re-derived by measurement rather than chosen by feel.
 *
 * Measured over 1,151 real third-party files (js/mjs/cjs/ts/json/map from
 * node_modules, 500 B to 3 MB): median 4.83, p99 5.38, p99.9 5.64, MAX 5.70.
 * Not one exceeded 5.8.
 *
 * The old value of 6.0 was not just loose, it was unreachable for the payload
 * shape this rule exists to find: base64 uses a 64-symbol alphabet, so its
 * entropy CANNOT exceed log2(64) = 6.0, and a strict "> 6.0" therefore never
 * fired on a base64 blob at all. Hex is capped at 4.0 for the same reason. At
 * 5.8 a base64 payload (6.00) is caught while every measured legitimate file
 * stays clean.
 */
const FILE_ENTROPY_THRESHOLD = 5.8;

/**
 * String-level threshold. Kept at 5.7: it applies to individual literals of
 * >= 100 chars rather than whole files, where a base64 payload sits at ~6.0 and
 * ordinary long strings (URLs, messages, minified identifiers) sit far lower.
 */
const STRING_ENTROPY_THRESHOLD = 5.7;

/** Minimum string length to check for entropy */
const MIN_STRING_LENGTH = 100;

/** Minimum file size to check (skip tiny files) */
const MIN_FILE_SIZE = 500;

/**
 * Analyze a file's content for high-entropy indicators.
 */
export function analyzeEntropy(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];

  if (content.length < MIN_FILE_SIZE) return findings;

  // Inlined assets (fonts, icons, images) as data: URIs are ordinary build
  // output and are high-entropy by construction. Measure the file WITHOUT them
  // so an inlined logo does not make a whole bundle look obfuscated; anything
  // genuinely hidden in the remaining code still counts.
  const withoutDataUris = content.replace(
    /data:[^;,\s"'`]+;base64,[A-Za-z0-9+/=]+/g,
    "",
  );

  // Check file-level entropy
  const fileEntropy = shannonEntropy(withoutDataUris);
  if (fileEntropy > FILE_ENTROPY_THRESHOLD) {
    findings.push({
      rule: "HIGH_ENTROPY_FILE",
      description: `File has unusually high entropy (${fileEntropy.toFixed(2)}). This may indicate compressed, encoded, or obfuscated content.`,
      severity: "medium",
      file: relativePath,
      recommendation:
        `Inspect this file for obfuscated payloads. Measured across 1,151 real third-party source files, none exceeded ${FILE_ENTROPY_THRESHOLD} (max 5.70).`,
    });
  }

  // Check individual long strings for high entropy
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    // Extract string literals and long tokens
    const strings = extractLongStrings(line);

    for (const str of strings) {
      if (str.length < MIN_STRING_LENGTH) continue;
      const strEntropy = shannonEntropy(str);

      if (strEntropy > STRING_ENTROPY_THRESHOLD) {
        findings.push({
          rule: "HIGH_ENTROPY_STRING",
          description: `High-entropy string detected (${strEntropy.toFixed(2)}, ${str.length} chars). Likely an encoded or obfuscated payload.`,
          severity: "high",
          file: relativePath,
          line: i + 1,
          match:
            str.length > 80
              ? str.substring(0, 40) + "..." + str.substring(str.length - 40)
              : str,
          recommendation:
            "Decode this string and inspect its contents. High-entropy strings in source code are a strong indicator of hidden payloads.",
        });
        break; // One per line is enough
      }
    }
  }

  return findings;
}

/**
 * Extract long strings (quoted literals and base64-like tokens) from a line.
 */
function extractLongStrings(line: string): string[] {
  const results: string[] = [];

  // Match quoted strings
  const quoted = line.match(/["'`]([^"'`]{100,})["'`]/g);
  if (quoted) {
    for (const q of quoted) {
      results.push(q.slice(1, -1));
    }
  }

  // Match long base64-like tokens (no quotes, alphanumeric + /+=)
  const b64 = line.match(/[A-Za-z0-9+/=_-]{100,}/g);
  if (b64) {
    results.push(...b64);
  }

  return results;
}
