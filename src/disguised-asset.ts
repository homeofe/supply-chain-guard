/**
 * Script code disguised as a web font (rule ASSET_DISGUISED_SCRIPT).
 *
 * The Contagious Interview "Fake Font" wave ships its stage-one loader as
 * public/fonts/fa-solid-400.woff2: a file with a font's name whose bytes are
 * obfuscated JavaScript, run by a hidden editor task. The task is caught by
 * EDITOR_TASK_EXECUTES_ASSET; this check catches the payload itself, so a
 * repository carrying the file is flagged even when the task was stripped or
 * moved to a carrier no rule reads yet.
 *
 * Precision: the filename is never a signature (FontAwesome ships exactly
 * these names). A file is reported only when all three hold:
 *   1. its extension is a font format;
 *   2. its first bytes match NONE of that family's signatures (woff "wOFF",
 *      woff2 "wOF2", TrueType 00 01 00 00 / "true", OpenType "OTTO", a
 *      collection "ttcf", EOT's "LP" magic at offset 34);
 *   3. it is plain text containing JavaScript syntax.
 * A Git LFS pointer (a text stub standing in for a real font) fails 3 without
 * a special case, since it carries no script syntax, and so does an empty file.
 * Truncated or corrupt real fonts are binary and fail 3 as well.
 */

import type { Finding } from "./types.js";

const FONT_EXTENSIONS = new Set([".woff", ".woff2", ".ttf", ".otf", ".eot"]);

const ascii = (bytes: Buffer, offset: number, text: string): boolean =>
  bytes.length >= offset + text.length &&
  bytes.subarray(offset, offset + text.length).toString("latin1") === text;

function hasFontSignature(bytes: Buffer): boolean {
  if (ascii(bytes, 0, "wOFF") || ascii(bytes, 0, "wOF2")) return true;
  if (ascii(bytes, 0, "OTTO") || ascii(bytes, 0, "true") || ascii(bytes, 0, "ttcf")) return true;
  if (bytes.length >= 4 && bytes[0] === 0x00 && bytes[1] === 0x01 && bytes[2] === 0x00 && bytes[3] === 0x00) return true;
  // EOT: MagicNumber 0x504C, little-endian at offset 34.
  if (bytes.length >= 36 && bytes[34] === 0x4c && bytes[35] === 0x50) return true;
  return false;
}

/** Share of bytes that are printable ASCII or common whitespace. */
function textShare(bytes: Buffer): number {
  const sample = bytes.subarray(0, Math.min(bytes.length, 65536));
  let text = 0;
  for (const b of sample) {
    if ((b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a || b === 0x0d) text++;
  }
  return sample.length === 0 ? 0 : text / sample.length;
}

const JS_SYNTAX_REGEX =
  /\bfunction\s*\(|=>|\b(?:var|let|const)\s+[\w$]+\s*=|\brequire\s*\(|\beval\s*\(|\bmodule\.exports\b|\bprocess\.\w|\bBuffer\.from\b|\bnew\s+Function\b/;

/**
 * Check one file's raw bytes. `relativePath` uses forward slashes. Returns at
 * most one finding.
 */
export function checkDisguisedAsset(bytes: Buffer, relativePath: string): Finding[] {
  const dot = relativePath.lastIndexOf(".");
  const ext = dot >= 0 ? relativePath.slice(dot).toLowerCase() : "";
  if (!FONT_EXTENSIONS.has(ext)) return [];
  if (hasFontSignature(bytes)) return [];
  if (textShare(bytes) < 0.95) return [];
  const text = bytes.subarray(0, Math.min(bytes.length, 262144)).toString("latin1");
  if (!JS_SYNTAX_REGEX.test(text)) return [];
  return [
    {
      rule: "ASSET_DISGUISED_SCRIPT",
      description:
        `${relativePath} is named as a font but is JavaScript: it carries no font signature and its content is script code. This is the Contagious Interview "Fake Font" payload disguise.`,
      severity: "high",
      file: relativePath,
      match: text.trim().slice(0, 80),
      confidence: 0.9,
      category: "malware",
      recommendation:
        "Do not run or open this project in an editor that runs tasks until the file is removed. Check .vscode/tasks.json, devcontainer.json and package.json scripts for anything that executes it.",
    },
  ];
}
