import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { checkDisguisedAsset } from "../disguised-asset.js";
import { scan } from "../scanner.js";

const NL = String.fromCharCode(10);
const E_ACUTE = String.fromCharCode(0xe9);

// The real Fake Font payloads in the Go proxy zips open with a run of spaces
// and then obfuscated JavaScript. This synthetic stand-in keeps that shape
// without carrying any real payload bytes.
const FAKE_FONT = Buffer.from(" ".repeat(300) + "var _0x1a2b=['a'];(function(a,b){return a+b;})(1,2);" + NL, "latin1");

/** Deterministic bytes covering the whole 0-255 range, like compressed font data. */
const binary = (n: number, mul: number, add: number) => Buffer.from(Array.from({ length: n }, (_, i) => (i * mul + add) % 256));

const rules = (bytes: Buffer, file: string) => checkDisguisedAsset(bytes, file).map((f) => `${f.rule}:${f.severity}`);

describe("ASSET_DISGUISED_SCRIPT", () => {
  it.each(["public/fonts/fa-solid-400.woff2", "assets/a.woff", "f.ttf", "f.otf", "f.eot"])(
    "flags JavaScript named %s",
    (file) => {
      expect(rules(FAKE_FONT, file)).toEqual(["ASSET_DISGUISED_SCRIPT:high"]);
    },
  );

  // Font magic numbers that are also valid JavaScript prefixes. A signature
  // check let an attacker prepend four bytes and walk past; the text test does
  // not care what the first bytes say.
  it.each([
    ["true;", "true;"],
    ["wOF2=0;", "wOF2=0;"],
    ["OTTO=0;", "OTTO=0;"],
    ["an accented comment (multi-byte UTF-8)", "/*" + E_ACUTE.repeat(400) + "*/"],
  ])("flags JavaScript behind %s", (_name, prefix) => {
    expect(rules(Buffer.concat([Buffer.from(prefix, "utf8"), FAKE_FONT]), "public/fonts/x.woff2")).toEqual(["ASSET_DISGUISED_SCRIPT:high"]);
  });

  // Real fonts are binary whatever their header; these are real font shapes and
  // the benign non-fonts found in font directories.
  it.each([
    ["a real WOFF2 font", Buffer.concat([Buffer.from("wOF2", "latin1"), binary(4096, 131, 7)])],
    ["a real TrueType font", Buffer.concat([Buffer.from([0, 1, 0, 0]), binary(4096, 97, 3)])],
    ["a Git LFS pointer", Buffer.from("version https://git-lfs.github.com/spec/v1" + NL + "oid sha256:" + "a".repeat(64) + NL + "size 75428" + NL, "latin1")],
    ["an empty file", Buffer.alloc(0)],
    // Random binary contains the bytes "=>" often (about 3 in 4 files of 50 KB), so
    // the text-share check, not the syntax check, keeps a corrupt real font clean.
    ["binary noise with script-like bytes (a corrupt real font)", Buffer.concat([binary(4096, 131, 7), Buffer.from("=> var a = 1", "latin1")])],
    // Binary with NO control bytes at all (every byte 0x80-0xFF) is still not
    // text: decoded as UTF-8 it is invalid sequences. Counted per byte it would
    // look printable and a real font of that shape would be flagged.
    ["high-byte binary with script-like bytes", Buffer.concat([Buffer.from(Array.from({ length: 4096 }, (_, i) => 0x80 + ((i * 37) % 128))), Buffer.from("=> var a = 1", "latin1")])],
    ["text without JavaScript", Buffer.from("placeholder font, replaced at build time" + NL, "latin1")],
    ["a saved HTML page (a broken download)", Buffer.from("<!DOCTYPE html><html><body>Not Found<script>window.x = () => 1;</script></body></html>", "latin1")],
    ["an SVG document", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>var a = 1;</script></svg>', "latin1")],
  ])("does NOT flag %s", (_name, bytes) => {
    expect(rules(bytes, "public/fonts/fa-solid-400.woff2")).toEqual([]);
  });

  it("does NOT look at non-font extensions", () => {
    expect(rules(FAKE_FONT, "public/app.js")).toEqual([]);
    expect(rules(FAKE_FONT, "public/logo.png")).toEqual([]);
  });

  describe("directory scan", () => {
    let dir: string;
    beforeAll(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-fakefont-"));
      fs.mkdirSync(path.join(dir, "public", "fonts"), { recursive: true });
      fs.writeFileSync(path.join(dir, "public", "fonts", "fa-solid-400.woff2"), FAKE_FONT);
      fs.writeFileSync(path.join(dir, "public", "fonts", "fa-brands-400.woff2"), Buffer.concat([Buffer.from("wOF2", "latin1"), binary(512, 131, 7)]));
    });
    afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

    it("reports the disguised file once and leaves the real font alone", async () => {
      const report = await scan({ target: dir, format: "json" });
      const hits = report.findings.filter((f) => f.rule === "ASSET_DISGUISED_SCRIPT");
      expect(hits.map((f) => f.file?.replace(/\\/g, "/"))).toEqual(["public/fonts/fa-solid-400.woff2"]);
    });
  });
});
