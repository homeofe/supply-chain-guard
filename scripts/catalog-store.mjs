// catalog-store.mjs - the ONE place that knows how the committed catalog is
// laid out on disk.
//
// The catalog used to be a single file, data/threat-catalog.jsonl. The full
// OpenSSF reconcile of 2026-10-05 took it to 41 MB, and GitHub warns at 50 MB
// per file and refuses 100 MB. It is now split into parts:
//
//   data/threat-catalog/part-000.jsonl, part-001.jsonl, ...
//
// The layout is a pure function of the content: every part except the last
// holds exactly PART_MAX_LINES lines, in catalog order. Concatenating the parts
// gives back the catalog line for line, so the digest, the release shards and
// every reader see exactly what the single file held. Writers never append to
// a part by hand; they hand the whole text to writeCatalogText, which re-cuts
// it, so two writers cannot produce two layouts for one catalog.
//
// Every script and test reads and writes through this module. A second copy of
// the path is how the single-file name ended up hard-coded in nine scripts.

import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Directory of the parts, repository-relative and forward-slashed for display. */
export const CATALOG_DIR = "data/threat-catalog";

/** Lines per part. 100,000 lines at the measured ~160 bytes is about 16 MB. */
export const PART_MAX_LINES = 100_000;

/** A part's file name. Three digits allow 100 million entries. */
export const PART_NAME = /^part-(\d{3})\.jsonl$/;

/** Repository-relative path of part `index`. */
export function catalogPartPath(index) {
  return `${CATALOG_DIR}/part-${String(index).padStart(3, "0")}.jsonl`;
}

/** The part files present, sorted by index, as repository-relative paths. */
export function listCatalogParts(root) {
  const dir = join(root, CATALOG_DIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => PART_NAME.test(name))
    .sort()
    .map((name) => `${CATALOG_DIR}/${name}`);
}

/** True when the store exists at all (an empty catalog is one empty part). */
export function catalogExists(root) {
  return listCatalogParts(root).length > 0;
}

/**
 * The whole catalog as one LF-terminated text, the parts concatenated in
 * order. Throws on a gap in the numbering: a missing middle part would
 * otherwise read as a smaller catalog, which is a silent false negative.
 */
export function readCatalogText(root) {
  const parts = listCatalogParts(root);
  parts.forEach((part, i) => {
    if (part !== catalogPartPath(i)) {
      throw new Error(`catalog parts are not contiguous: expected ${catalogPartPath(i)}, found ${part}`);
    }
  });
  return parts
    .map((part) => {
      const text = readFileSync(join(root, part), "utf8");
      return text.length > 0 && !text.endsWith("\n") ? `${text}\n` : text;
    })
    .join("");
}

/** The non-empty catalog lines, CR-tolerant, in order. */
export function readCatalogLines(root) {
  return readCatalogText(root)
    .split(/\r?\n/)
    .filter((line) => line.trim() !== "");
}

/** The catalog entries, parsed. */
export function readCatalogEntries(root) {
  return readCatalogLines(root).map((line) => JSON.parse(line));
}

/** Cut an ordered list of lines into the canonical parts. */
export function layoutCatalogParts(lines) {
  const parts = [];
  for (let i = 0; i < lines.length; i += PART_MAX_LINES) {
    parts.push(lines.slice(i, i + PART_MAX_LINES));
  }
  if (parts.length === 0) parts.push([]);
  return parts.map((chunk, i) => ({
    path: catalogPartPath(i),
    text: chunk.length > 0 ? `${chunk.join("\n")}\n` : "",
  }));
}

/**
 * Replace the whole catalog with `text` and re-cut it into canonical parts.
 * Parts beyond the new last one are deleted, so shrinking cannot leave a
 * stale tail that readCatalogText would still concatenate.
 */
export function writeCatalogText(root, text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
  const layout = layoutCatalogParts(lines);
  mkdirSync(join(root, CATALOG_DIR), { recursive: true });
  for (const part of layout) writeFileSync(join(root, part.path), part.text);
  for (const existing of listCatalogParts(root)) {
    if (!layout.some((part) => part.path === existing)) unlinkSync(join(root, existing));
  }
  return layout.map((part) => part.path);
}

/** Append lines to the catalog through the canonical layout. */
export function appendCatalogLines(root, lines) {
  return writeCatalogText(root, `${readCatalogText(root)}${lines.join("\n")}\n`);
}

/**
 * Differences between the parts on disk and the canonical layout of their own
 * content. Empty means canonical. Used by the build gate, so a hand edit that
 * overfills a part or leaves a short part in the middle is refused.
 */
export function checkCatalogLayout(root) {
  const parts = listCatalogParts(root);
  if (parts.length === 0) return [`${CATALOG_DIR}/ has no part files; an empty catalog is one empty part-000.jsonl`];
  let text;
  try {
    text = readCatalogText(root);
  } catch (err) {
    return [err instanceof Error ? err.message : String(err)];
  }
  const lines = text.split("\n").filter((line) => line.trim() !== "");
  const layout = layoutCatalogParts(lines);
  const problems = [];
  if (layout.length !== parts.length) {
    problems.push(`${parts.length} part file(s) on disk, the canonical layout has ${layout.length}`);
  }
  for (const part of layout) {
    if (!parts.includes(part.path)) continue;
    if (readFileSync(join(root, part.path), "utf8") !== part.text) {
      problems.push(`${part.path} differs from the canonical cut (${PART_MAX_LINES} lines per part, LF, no blank lines)`);
    }
  }
  return problems;
}
