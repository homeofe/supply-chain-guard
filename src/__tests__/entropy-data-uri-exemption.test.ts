import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import * as entropy from "../entropy.js";
import { analyzeEntropy } from "../entropy.js";
import { performanceBudget } from "./performance-budget.js";

const B64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Every base64 symbol equally often, so entropy sits at the 6.0 ceiling. */
function uniformBase64(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += B64[(i * 37) % 64];
  return out;
}

const PAYLOAD = uniformBase64(640);
const BODY = Buffer.from(PAYLOAD, "base64");

const u32be = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u32le = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u16be = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const ascii = (s: string): Buffer => Buffer.from(s, "latin1");
const b64 = (...parts: Buffer[]): string => Buffer.concat(parts).toString("base64");

/** A PNG chunk; the CRC is not checked by the exemption. */
const chunk = (type: string, data: Buffer): Buffer =>
  Buffer.concat([u32be(data.length), ascii(type), data, Buffer.alloc(4)]);
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_BYTES = Buffer.concat([PNG_SIG, chunk("IHDR", Buffer.alloc(13)), chunk("IDAT", BODY), chunk("IEND", Buffer.alloc(0))]);
const PNG = PNG_BYTES.toString("base64");

/** WOFF and WOFF2 declare their total length at offset 8. */
const woff = (magic: string): string => {
  const head = Buffer.concat([ascii(magic), ascii("true"), u32be(0)]);
  const whole = Buffer.concat([head, BODY]);
  whole.writeUInt32BE(whole.length, 8);
  return whole.toString("base64");
};
const WOFF = woff("wOFF");
const WOFF2 = woff("wOF2");

/** One table whose record reaches the end of the file. */
const TTF = b64(
  Buffer.from([0x00, 0x01, 0x00, 0x00]), u16be(1), Buffer.alloc(6),
  ascii("glyf"), u32be(0), u32be(28), u32be(BODY.length), BODY,
);

const JPEG = b64(Buffer.from([0xff, 0xd8, 0xff, 0xe0]), BODY, Buffer.from([0xff, 0xd9]));

/** JPEG XL container: signature box, ftyp box, codestream box. */
const box = (type: string, data: Buffer): Buffer => Buffer.concat([u32be(8 + data.length), ascii(type), data]);
const JXL = b64(
  Buffer.from([0, 0, 0, 0x0c]), ascii("JXL "), Buffer.from([0x0d, 0x0a, 0x87, 0x0a]),
  box("ftyp", Buffer.concat([ascii("jxl "), u32be(0), ascii("jxl ")])),
  box("jxlc", BODY),
);

const WEBP = b64(ascii("RIFF"), u32le(4 + 8 + BODY.length), ascii("WEBP"), ascii("VP8L"), u32le(BODY.length), BODY);
const rules = (content: string, file = "src/logo.ts") =>
  analyzeEntropy(content, file).map((finding) => finding.rule);

describe("HIGH_ENTROPY_STRING data URI exemption", () => {
  it.each([
    ["image/png", `export const LOGO = "data:image/png;base64,${PNG}";\n`],
    ["font/woff2", `@font-face { src: url(data:font/woff2;base64,${WOFF2}); }\n`],
    ["application/font-woff (legacy)", `@font-face { src: url(data:application/font-woff;base64,${WOFF}); }\n`],
    ["application/x-font-ttf (legacy)", `@font-face { src: url(data:application/x-font-ttf;base64,${TTF}); }\n`],
    ["image/jpeg", `export const PHOTO = "data:image/jpeg;base64,${JPEG}";\n`],
    ["image/webp", `export const PHOTO = "data:image/webp;base64,${WEBP}";\n`],
    ["image/jxl (container)", `export const PHOTO = "data:image/jxl;base64,${JXL}";\n`],
  ])("reports an inlined %s data URI at low only", (_type, content) => {
    const found = analyzeEntropy(content, "src/logo.ts").map((finding) => `${finding.rule}:${finding.severity}`);
    expect(found).toEqual(["HIGH_ENTROPY_STRING:low"]);
  });

  it("still reports a payload that merely sits on the same line as an image data URI", () => {
    const content =
      `const a = "data:image/png;base64,${PNG}"; const b = "${uniformBase64(200)}";\n`;
    expect(rules(content)).toContain("HIGH_ENTROPY_STRING");
  });

  // A real header is 8 bytes anyone can prepend: the container has to account
  // for every byte, so a payload after a header or after the end stays visible.
  it.each([
    ["a PNG signature followed by the payload", b64(PNG_SIG, BODY)],
    ["a complete PNG with the payload appended after IEND", b64(PNG_BYTES, BODY)],
    ["a JPEG start marker without the end marker", b64(Buffer.from([0xff, 0xd8, 0xff, 0xe0]), BODY)],
    ["a WOFF2 header whose declared length is short", b64(ascii("wOF2"), ascii("true"), u32be(64), BODY)],
    ["a JPEG XL container with bytes after its last box", b64(Buffer.from(JXL, "base64"), BODY)],
    ["a font whose tables end well before the file does", b64(
      Buffer.from([0x00, 0x01, 0x00, 0x00]), u16be(1), Buffer.alloc(6),
      ascii("glyf"), u32be(0), u32be(28), u32be(64), BODY,
    )],
    ["a WEBP whose RIFF size is short", b64(ascii("RIFF"), u32le(64), ascii("WEBP"), ascii("VP8L"), u32le(BODY.length), BODY)],
  ])("reports %s at high", (_label, payload) => {
    const content = `const s = "data:image/png;base64,${payload}";\n`;
    const found = analyzeEntropy(content, "src/logo.ts").filter((finding) => finding.rule === "HIGH_ENTROPY_STRING");
    expect(found.map((finding) => finding.severity)).toEqual(["high"]);
  });

  // A well-formed container is easy to forge; a file that could unpack its
  // own "image" keeps the high verdict for it.
  it.each([
    ["vm", 'require("vm").runInThisContext(Buffer.from(LOGO.split(",")[1], "base64").toString());'],
    ["eval of atob", 'eval(atob(LOGO.split(",")[1]));'],
    ["child_process", 'require("child_process").execSync(Buffer.from(LOGO.slice(23), "base64").toString());'],
    ["import of a data URL", 'const s = Buffer.from(LOGO.slice(23), enc); import("data:text/javascript," + s);'],
    ["TextDecoder", "setTimeout(new TextDecoder().decode(Uint8Array.from(x)), 0);"],
    ["Python decodebytes", 'f = compile(base64.decodebytes(LOGO[23:].encode()), "x", "exec")'],
    ["an object URL", "import(URL.createObjectURL(new Blob([b])));"],
    ["Reflect.construct", "Reflect.construct(Function2, [x])();"],
    ["Python subprocess", "subprocess.run(x, shell=True)"],
    ["PHP base64_decode", "file_put_contents($f, base64_decode($x));"],
    ["Ruby instance_eval", "instance_eval(x)"],
    ["WebAssembly", "WebAssembly.instantiate(x);"],
    ["base64 -D", "run(`base64 -D x`)"],
  ])("keeps an inlined image at high in a file that decodes or runs code (%s)", (_label, sink) => {
    const content = `const LOGO = "data:image/jpeg;base64,${JPEG}";\n${sink}\n`;
    const found = analyzeEntropy(content, "src/logo.js").filter((finding) => finding.rule === "HIGH_ENTROPY_STRING");
    expect(found.map((finding) => finding.severity)).toEqual(["high"]);
  });

  it("does not let a payload ride behind the padding of a real image", () => {
    // 538 bytes, so the base64 ends in "==" before the appended payload.
    const padded = Buffer.concat([PNG_SIG, chunk("IHDR", Buffer.alloc(13)), chunk("IDAT", Buffer.concat([BODY, Buffer.alloc(1)])), chunk("IEND", Buffer.alloc(0))]);
    const b64png = padded.toString("base64");
    expect(b64png.endsWith("==")).toBe(true);
    const content = `const s = "data:image/png;base64,${b64png}${PAYLOAD}";\n`;
    const found = analyzeEntropy(content, "src/logo.ts").filter((finding) => finding.rule === "HIGH_ENTROPY_STRING");
    expect(found.map((finding) => finding.severity)).toEqual(["high"]);
  });

  it("does not accept a zero-size first box as a whole BMFF file", () => {
    const content = `const s = "data:image/avif;base64,${b64(u32be(0), ascii("ftyp"), BODY)}";\n`;
    const found = analyzeEntropy(content, "src/logo.ts").filter((finding) => finding.rule === "HIGH_ENTROPY_STRING");
    expect(found.map((finding) => finding.severity)).toEqual(["high"]);
  });

  // The label is chosen by whoever wrote the file, so it proves nothing alone.
  it.each(["image/png", "image/jpeg", "font/woff2", "application/font-woff"])(
    "reports a %s data URI whose bytes carry no image or font signature",
    (type) => {
      const content = `const s = "data:${type};base64,${PAYLOAD}";\n`;
      expect(rules(content)).toContain("HIGH_ENTROPY_STRING");
    },
  );

  it("reports a bare 200-character base64 string at high", () => {
    const content = `${"// padding line\n".repeat(40)}const P = "${uniformBase64(200)}";\n`;
    const found = analyzeEntropy(content, "src/p.ts")
      .filter((finding) => finding.rule === "HIGH_ENTROPY_STRING");
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe("high");
  });

  // image/svg+xml is a document that can carry script, so it is not exempt.
  it.each(["text/javascript", "application/octet-stream", "image/svg+xml"])(
    "reports a %s data URI in the per-string pass",
    (type) => {
      const content = `const s = "data:${type};base64,${PAYLOAD}";\n`;
      expect(rules(content)).toContain("HIGH_ENTROPY_STRING");
    },
  );

  it.each(["text/javascript", "application/octet-stream"])(
    "no longer hides a %s data URI from the file-level pass",
    (type) => {
      // The file is almost entirely the payload, so only an exemption keeps it
      // below the file threshold. Before the shared exemption every media type
      // was stripped here.
      const content = `s="data:${type};base64,${PAYLOAD}"\n`;
      expect(rules(content)).toContain("HIGH_ENTROPY_FILE");
    },
  );

  it("shares one exemption function between the file-level and per-string passes", () => {
    const strip = (entropy as Record<string, unknown>).stripExemptDataUris;
    expect(typeof strip).toBe("function");
    const fn = strip as (content: string) => string;
    expect(fn(`x "data:image/png;base64,${PNG}" y`)).toBe(`x "" y`);
    expect(fn(`x "data:font/ttf;base64,${TTF}" y`)).toBe(`x "" y`);
    const fake = `x "data:image/png;base64,${PAYLOAD}" y`;
    expect(fn(fake)).toBe(fake);
    const js = `x "data:text/javascript;base64,${PAYLOAD}" y`;
    expect(fn(js)).toBe(js);
    // The replacement never removes a newline, so line numbers stay exact.
    const twoLines = `a "data:image/png;base64,${PNG}"\nb`;
    expect(fn(twoLines).split("\n")).toHaveLength(2);
  });

  it("keeps the exemption linear on a 5 MiB adversarial line", { timeout: performanceBudget(20_000) }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const unit = "data:image/png;base64data:image/";
    const content = unit.repeat(Math.ceil(fiveMiB / unit.length)).slice(0, fiveMiB);
    const started = performance.now();
    analyzeEntropy(content, "src/big.js");
    expect(performance.now() - started).toBeLessThan(performanceBudget(5_000));
  });
});
