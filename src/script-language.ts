/**
 * Which language a file is read as when its extension does not say.
 *
 * The content scan is gated on SCANNABLE_EXTENSIONS, which is keyed on the file
 * extension. Executable scripts very often carry none: a git hook
 * (`scripts/hooks/pre-commit`, `.husky/pre-push`), a package `bin/` launcher, a
 * CI helper named `ci/run`. Before this module those files were counted in the
 * walk and never opened, so a malicious payload in a hook shipped inside a
 * package tarball produced no finding at all. Bats suites (`*.bats`) had the
 * same gap for a different reason: the extension is not a shell one, although
 * every line of the file is bash.
 *
 * The answer is an EFFECTIVE EXTENSION, not a boolean, because rules scoped
 * with `onlyExtensions` must see the language the file is written in: a
 * `#!/usr/bin/env node` hook is JavaScript and a `.bats` suite is bash.
 */

import * as fs from "node:fs";

/**
 * Extensions whose content is another language's source, read as that
 * language. A `.bats` file is a bash script with a test DSL on top.
 */
const EXTENSION_ALIASES: ReadonlyMap<string, string> = new Map([
  [".bats", ".bash"],
]);

/**
 * Interpreter basename (after `env`, version suffix removed) to the extension
 * whose rules apply. An interpreter not listed here is not read: an unknown
 * language gets no language-specific rule, and guessing would only add noise.
 */
const INTERPRETER_EXTENSIONS: ReadonlyMap<string, string> = new Map([
  ["sh", ".sh"],
  ["dash", ".sh"],
  ["ash", ".sh"],
  ["ksh", ".sh"],
  ["mksh", ".sh"],
  ["bash", ".bash"],
  ["zsh", ".zsh"],
  ["fish", ".fish"],
  ["node", ".js"],
  ["nodejs", ".js"],
  ["bun", ".js"],
  ["deno", ".ts"],
  ["tsx", ".ts"],
  ["ts-node", ".ts"],
  ["python", ".py"],
  ["ruby", ".rb"],
  ["perl", ".pl"],
  ["php", ".php"],
  ["pwsh", ".ps1"],
]);

/**
 * Git hook names (githooks(5)). Git runs an extensionless hook with no shebang
 * through /bin/sh, and hook managers such as husky write hooks that way, so a
 * file carrying one of these names and no extension is shell even without a
 * `#!` line. `update` is left out on purpose: it is the one hook name that is
 * also an ordinary word for a file.
 */
const GIT_HOOK_NAMES: ReadonlySet<string> = new Set([
  "applypatch-msg",
  "pre-applypatch",
  "post-applypatch",
  "pre-commit",
  "pre-merge-commit",
  "prepare-commit-msg",
  "commit-msg",
  "post-commit",
  "pre-rebase",
  "post-checkout",
  "post-merge",
  "pre-push",
  "pre-receive",
  "proc-receive",
  "post-receive",
  "post-update",
  "reference-transaction",
  "push-to-checkout",
  "pre-auto-gc",
  "post-rewrite",
  "sendemail-validate",
  "fsmonitor-watchman",
  "post-index-change",
]);

/**
 * Longest first line examined for an interpreter. Real shebang lines are far
 * shorter (the kernel historically truncated at 127 bytes); anything longer is
 * not a line this module needs to understand.
 */
export const SHEBANG_MAX_BYTES = 256;

/**
 * Effective extension named by a shebang line, or null when the bytes do not
 * start with `#!` or name an interpreter this scanner has rules for.
 *
 * Handles `#!/bin/sh -e`, `#!/usr/bin/env node`, `#!/usr/bin/env -S deno run`,
 * `#!/usr/bin/env VAR=1 python3` and versioned names such as `python3.12`.
 */
export function shebangExtension(head: Uint8Array): string | null {
  if (head.length < 3 || head[0] !== 0x23 || head[1] !== 0x21) return null;
  const limit = Math.min(head.length, SHEBANG_MAX_BYTES);
  let end = 2;
  while (end < limit && head[end] !== 0x0a && head[end] !== 0x0d) end++;
  const line = Buffer.from(head.subarray(2, end)).toString("latin1").trim();
  const tokens = line.split(/[ \t]+/).filter(Boolean);
  if (tokens.length === 0) return null;

  let interpreter = baseName(tokens[0]!);
  if (interpreter === "env") {
    // env's own options and NAME=value assignments come before the program.
    let i = 1;
    while (i < tokens.length && (tokens[i]!.startsWith("-") || tokens[i]!.includes("="))) i++;
    if (i >= tokens.length) return null;
    interpreter = baseName(tokens[i]!);
  }
  // python3, python3.12, ruby3.3, perl5.36, php8.2, node22: the rules are the
  // same for every version of a language.
  const unversioned = interpreter.toLowerCase().replace(/[0-9][0-9.]*$/, "");
  return INTERPRETER_EXTENSIONS.get(unversioned) ?? null;
}

function baseName(token: string): string {
  const slash = Math.max(token.lastIndexOf("/"), token.lastIndexOf("\\"));
  return slash >= 0 ? token.slice(slash + 1) : token;
}

/**
 * Read at most SHEBANG_MAX_BYTES from the start of a file. A read failure
 * returns null: the file's language is then unknown, which is the same state
 * the scan was in before this module existed, so it is not reported as a
 * coverage gap here.
 */
function readHead(filePath: string): Uint8Array | null {
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, "r");
    const buffer = Buffer.alloc(SHEBANG_MAX_BYTES);
    const read = fs.readSync(fd, buffer, 0, SHEBANG_MAX_BYTES, 0);
    return buffer.subarray(0, read);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // Closing a descriptor that was opened read-only cannot lose data.
      }
    }
  }
}

/**
 * The extension a file outside SCANNABLE_EXTENSIONS is read as, or null when it
 * is not read.
 *
 * - `.bats` reads as `.bash`.
 * - A file with NO extension is read when its first line is a shebang naming a
 *   known interpreter, or, failing that, when its name is a git hook name
 *   (shell).
 * - Any other extension is not read: an unknown extension with a shebang is
 *   left alone, so this cannot widen the scan to data files.
 *
 * `head` is the file's leading bytes when the caller already holds them (the
 * directory scan reads every file up to MAX_FILE_SIZE for the digest check).
 * Otherwise at most SHEBANG_MAX_BYTES are read, so an oversized binary is never
 * loaded to answer this question.
 */
export function scriptLanguageExtension(
  filePath: string,
  basename: string,
  extension: string,
  head?: Uint8Array,
): string | null {
  const alias = EXTENSION_ALIASES.get(extension);
  if (alias !== undefined) return alias;
  if (extension !== "") return null;

  const bytes = head ?? readHead(filePath);
  if (bytes !== null) {
    const fromShebang = shebangExtension(bytes);
    if (fromShebang !== null) return fromShebang;
    // A shebang that names an interpreter without rules (awk, make, tclsh)
    // is a positive statement that the file is NOT shell, so the hook name
    // does not override it.
    if (bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x21) return null;
  }
  return GIT_HOOK_NAMES.has(basename) ? ".sh" : null;
}
