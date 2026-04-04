/**
 * Shannon entropy analysis for detecting obfuscated/encoded payloads.
 *
 * High entropy (>6.0) in source code files indicates compressed, encoded,
 * or obfuscated content — a common technique in supply-chain malware.
 */

import type { Finding } from "./types.js";

/**
 * Calculate Shannon entropy of a string.
 * Returns a value between 0 (uniform) and ~8 (random/encrypted).
 */
export function shannonEntropy(data: string): number {
  if (data.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of data) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = data.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/** Threshold for file-level entropy alert */
const FILE_ENTROPY_THRESHOLD = 6.0;

/** Threshold for single-string entropy alert */
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

  // Check file-level entropy
  const fileEntropy = shannonEntropy(content);
  if (fileEntropy > FILE_ENTROPY_THRESHOLD) {
    findings.push({
      rule: "HIGH_ENTROPY_FILE",
      description: `File has unusually high entropy (${fileEntropy.toFixed(2)}). This may indicate compressed, encoded, or obfuscated content.`,
      severity: "medium",
      file: relativePath,
      recommendation:
        "Inspect this file for obfuscated payloads. Legitimate source code typically has entropy below 6.0.",
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
