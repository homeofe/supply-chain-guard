/**
 * scripts/catalog-store.mjs: the committed catalog split into parts.
 *
 * The single file reached 41 MB on 2026-10-05, against GitHub's 50 MB warning
 * and 100 MB refusal. The claims that matter: the parts are the catalog line
 * for line, the layout is a function of the content alone, and a gap or a
 * hand edit is refused rather than read as a smaller catalog.
 */
import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";

import {
  CATALOG_DIR,
  PART_MAX_LINES,
  appendCatalogLines,
  catalogPartPath,
  checkCatalogLayout,
  layoutCatalogParts,
  listCatalogParts,
  readCatalogLines,
  readCatalogText,
  writeCatalogText,
} from "../../scripts/catalog-store.mjs";
import { CATALOG_DIGEST } from "../catalog-digest.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "scg-store-"));
  dirs.push(d);
  return d;
};
const lines = (n: number, from = 0) =>
  Array.from({ length: n }, (_, i) => JSON.stringify({ type: "package", value: `p${from + i}@1`, severity: "critical" }));

describe("layoutCatalogParts", () => {
  it("fills every part but the last, in order", () => {
    const all = lines(PART_MAX_LINES * 2 + 5);
    const layout = layoutCatalogParts(all);
    expect(layout.map((p: { path: string }) => p.path)).toEqual([catalogPartPath(0), catalogPartPath(1), catalogPartPath(2)]);
    expect(layout[0].text.split("\n").filter(Boolean)).toHaveLength(PART_MAX_LINES);
    expect(layout[2].text.split("\n").filter(Boolean)).toHaveLength(5);
    expect(layout.map((p: { text: string }) => p.text).join("")).toBe(`${all.join("\n")}\n`);
  });

  it("is one empty part for an empty catalog", () => {
    expect(layoutCatalogParts([])).toEqual([{ path: catalogPartPath(0), text: "" }]);
  });
});

describe("write, read, append", () => {
  it("round-trips the text exactly and re-cuts on append", () => {
    const root = tmp();
    const first = lines(PART_MAX_LINES - 1);
    writeCatalogText(root, `${first.join("\n")}\n`);
    expect(listCatalogParts(root)).toEqual([catalogPartPath(0)]);
    appendCatalogLines(root, lines(3, PART_MAX_LINES));
    expect(listCatalogParts(root)).toEqual([catalogPartPath(0), catalogPartPath(1)]);
    expect(readCatalogLines(root)).toHaveLength(PART_MAX_LINES + 2);
    expect(checkCatalogLayout(root)).toEqual([]);
  });

  // A rollback writes the ORIGINAL text back. The part a failed import added
  // must disappear, or the reader would still concatenate it.
  it("deletes parts beyond the new end when the catalog shrinks", () => {
    const root = tmp();
    writeCatalogText(root, `${lines(PART_MAX_LINES + 10).join("\n")}\n`);
    expect(listCatalogParts(root)).toHaveLength(2);
    writeCatalogText(root, `${lines(4).join("\n")}\n`);
    expect(listCatalogParts(root)).toEqual([catalogPartPath(0)]);
    expect(readCatalogLines(root)).toHaveLength(4);
  });

  it("refuses a gap in the numbering instead of reading a smaller catalog", () => {
    const root = tmp();
    writeCatalogText(root, `${lines(PART_MAX_LINES * 2 + 1).join("\n")}\n`);
    fs.rmSync(path.join(root, catalogPartPath(1)));
    expect(() => readCatalogText(root)).toThrow(/not contiguous/);
    expect(checkCatalogLayout(root).join(" ")).toMatch(/not contiguous/);
  });
});

describe("checkCatalogLayout", () => {
  it("reports a part overfilled by hand", () => {
    const root = tmp();
    writeCatalogText(root, `${lines(PART_MAX_LINES + 2).join("\n")}\n`);
    // Move one line from part-001 into part-000: same catalog, wrong cut.
    const p0 = path.join(root, catalogPartPath(0));
    const p1 = path.join(root, catalogPartPath(1));
    const [moved, ...rest] = fs.readFileSync(p1, "utf8").split("\n").filter(Boolean);
    fs.appendFileSync(p0, `${moved}\n`);
    fs.writeFileSync(p1, `${rest.join("\n")}\n`);
    expect(checkCatalogLayout(root).join(" ")).toMatch(/differs from the canonical cut/);
  });

  it("reports a missing store", () => {
    expect(checkCatalogLayout(tmp()).join(" ")).toMatch(/no part files/);
  });
});

describe("the committed catalog", () => {
  const repoRoot = path.resolve(__dirname, "..", "..");

  it("is laid out canonically under the store directory", () => {
    expect(fs.existsSync(path.join(repoRoot, "data", "threat-catalog.jsonl"))).toBe(false);
    expect(listCatalogParts(repoRoot).every((p: string) => p.startsWith(`${CATALOG_DIR}/`))).toBe(true);
    expect(checkCatalogLayout(repoRoot)).toEqual([]);
  }, 60_000);

  it("is the catalog the shipped digest describes", () => {
    const entries = readCatalogLines(repoRoot).map((l: string) => JSON.parse(l));
    expect(entries).toHaveLength(CATALOG_DIGEST.entryCount);
    expect(createHash("sha256").update(JSON.stringify(entries), "utf8").digest("hex")).toBe(
      CATALOG_DIGEST.entriesSha256,
    );
  }, 60_000);

  it("keeps every part under GitHub's 50 MB file warning", () => {
    for (const part of listCatalogParts(repoRoot)) {
      expect(fs.statSync(path.join(repoRoot, part)).size).toBeLessThan(50 * 1024 * 1024);
    }
  });
});
