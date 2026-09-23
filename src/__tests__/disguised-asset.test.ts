import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { checkDisguisedAsset } from "../disguised-asset.js";
import { scan } from "../scanner.js";

// The real Fake Font payloads in the Go proxy zips open with a run of spaces
// and then obfuscated JavaScript. This synthetic stand-in keeps that shape
// without carrying any real payload bytes.
const FAKE_FONT = Buffer.from(" ".repeat(300) + "var _0x1a2b=['\\x68'];(function(a,b){return a+b;})(1,2);\n", "latin1");

const rules = (bytes: Buffer, file: string) => checkDisguisedAsset(bytes, file).map((f) => `${f.rule}:${f.severity}`);

describe("ASSET_DISGUISED_SCRIPT", () => {
  it.each(["public/fonts/fa-solid-400.woff2", "assets/a.woff", "f.ttf", "f.otf", "f.eot"])(
    "flags JavaScript named %s",
    (file) => {
      expect(rules(FAKE_FONT, file)).toEqual(["ASSET_DISGUISED_SCRIPT:high"]);
    },
  );

  it.each([
    ["a real WOFF2 header", Buffer.concat([Buffer.from("wOF2", "latin1"), FAKE_FONT])],
    ["a real WOFF header", Buffer.concat([Buffer.from("wOFF", "latin1"), FAKE_FONT])],
    ["a TrueType header", Buffer.concat([Buffer.from([0, 1, 0, 0]), FAKE_FONT])],
    ["an OpenType header", Buffer.concat([Buffer.from("OTTO", "latin1"), FAKE_FONT])],
    ["an Apple TrueType header", Buffer.concat([Buffer.from("true", "latin1"), FAKE_FONT])],
    ["a font collection header", Buffer.concat([Buffer.from("ttcf", "latin1"), FAKE_FONT])],
    ["an EOT header (LP magic at offset 34)", Buffer.concat([Buffer.alloc(34, 0x20), Buffer.from("LP", "latin1"), FAKE_FONT])],
    ["a Git LFS pointer", Buffer.from("version https://git-lfs.github.com/spec/v1\noid sha256:" + "a".repeat(64) + "\nsize 75428\n", "latin1")],
    ["an empty file", Buffer.alloc(0)],
    // Random binary contains the bytes "=>" often (about 3 in 4 files of 50 KB), so the
    // text-share check, not the syntax check, is what keeps a corrupt real font clean.
    ["binary noise with script-like bytes (a corrupt real font)", Buffer.concat([Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 131 + 7) % 256)), Buffer.from("=> var a = 1", "latin1")])],
    ["text without JavaScript", Buffer.from("placeholder font, replaced at build time\n", "latin1")],
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
      fs.writeFileSync(path.join(dir, "public", "fonts", "fa-brands-400.woff2"), Buffer.concat([Buffer.from("wOF2", "latin1"), Buffer.alloc(64)]));
    });
    afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

    it("reports the disguised file once and leaves the real font alone", async () => {
      const report = await scan({ target: dir, format: "json" });
      const hits = report.findings.filter((f) => f.rule === "ASSET_DISGUISED_SCRIPT");
      expect(hits.map((f) => f.file?.replace(/\\/g, "/"))).toEqual(["public/fonts/fa-solid-400.woff2"]);
    });
  });
});
