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
 * these names). A file is reported only when all of these hold:
 *   1. its extension is a font format;
 *   2. it is text: at least 95% of its UTF-8 characters are printable, while
 *      every real font format (TrueType/OpenType tables, WOFF/WOFF2 compressed
 *      data, EOT) is binary;
 *   3. it contains JavaScript syntax;
 *   4. it is not a saved HTML/XML/SVG document (a broken download committed
 *      under a font's name is common and is not this payload).
 * The first bytes are deliberately NOT trusted: "true;", "OTTO=0;" and
 * "wOF2=0;" are font magic numbers AND valid JavaScript prefixes, so a
 * signature check only told an attacker which four bytes to prepend. A Git
 * LFS pointer and an empty file fail 3.
 */

import type { Finding } from "./types.js";

const FONT_EXTENSIONS = new Set([".woff", ".woff2", ".ttf", ".otf", ".eot"]);

/** Bytes inspected: enough for the payloads seen, bounded for huge files. */
const SAMPLE_BYTES = 262144;

/**
 * Share of UTF-8 characters that are printable. Counted over decoded
 * characters, not bytes, so a comment full of accented letters (multi-byte
 * UTF-8) cannot push script text under the threshold. Invalid UTF-8 decodes to
 * U+FFFD and counts as binary, which is what keeps a real font out.
 */
function textShare(text: string): number {
  if (text.length === 0) return 0;
  let binary = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0xfffd || (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0x7f) binary++;
  }
  return 1 - binary / text.length;
}

const JS_SYNTAX_REGEX =
  /\bfunction\s*\(|=>|\b(?:var|let|const)\s+[\w$]+\s*=|\brequire\s*\(|\beval\s*\(|\bmodule\.exports\b|\bprocess\.\w|\bBuffer\.from\b|\bnew\s+Function\b/;

const MARKUP_DOCUMENT_REGEX = /^\s*<(?:!doctype\s+html|html\b|\?xml\b|svg\b)/i;

/**
 * Check one file's raw bytes. `relativePath` uses forward slashes. Returns at
 * most one finding.
 */
export function checkDisguisedAsset(bytes: Buffer, relativePath: string): Finding[] {
  const dot = relativePath.lastIndexOf(".");
  const ext = dot >= 0 ? relativePath.slice(dot).toLowerCase() : "";
  if (!FONT_EXTENSIONS.has(ext)) return [];
  const text = bytes.subarray(0, Math.min(bytes.length, SAMPLE_BYTES)).toString("utf8");
  if (textShare(text) < 0.95) return [];
  if (MARKUP_DOCUMENT_REGEX.test(text)) return [];
  if (!JS_SYNTAX_REGEX.test(text)) return [];
  return [
    {
      rule: "ASSET_DISGUISED_SCRIPT",
      description:
        `${relativePath} is named as a font but is JavaScript: it is plain text, which no real font is, and its content is script code. This is the Contagious Interview "Fake Font" payload disguise.`,
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
