import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { deflateRawSync, gzipSync } from "node:zlib";

const childProcess = vi.hoisted(() => ({ execFileSync: vi.fn() }));
vi.mock("node:child_process", () => ({ execFileSync: childProcess.execFileSync }));

import {
  ARCHIVE_MAX_ENTRIES,
  ARCHIVE_MAX_EXPANDED_BYTES,
  ARCHIVE_MAX_PATH_COMPONENTS,
  ArchiveSecurityError,
  extractTar,
  extractTarGz,
  extractZip,
  preflightTarArchive,
  preflightZipArchive,
} from "../archive-extractor.js";

type ZipFixtureEntry = {
  name: string;
  nameBytes?: Buffer;
  flags?: number;
  hostSystem?: number;
  data?: Buffer | string;
  mode?: number;
  centralExtra?: Buffer;
  localExtra?: Buffer;
  declaredUncompressedSize?: number;
  compressionMethod?: 0 | 8;
  localOffsetOverride?: number;
};

type TarFixtureEntry = {
  name: string;
  nameBytes?: Buffer;
  format?: "posix" | "gnu" | "v7";
  gnuAtime?: number;
  type?: string;
  data?: Buffer | string;
  link?: string;
  linkBytes?: Buffer;
  declaredSize?: number;
  omitPayload?: boolean;
};

function makeZip(entries: ZipFixtureEntry[]): Buffer {
  const localRecords: Buffer[] = [];
  const centralRecords: Buffer[] = [];
  let localOffset = 0;
  for (const fixture of entries) {
    const name = fixture.nameBytes ?? Buffer.from(fixture.name);
    const flags = fixture.flags ?? 0x0800;
    const data = Buffer.isBuffer(fixture.data) ? fixture.data : Buffer.from(fixture.data ?? "");
    const compressionMethod = fixture.compressionMethod ?? 0;
    const compressed = compressionMethod === 8 ? deflateRawSync(data) : data;
    const localExtra = fixture.localExtra ?? Buffer.alloc(0);
    const centralExtra = fixture.centralExtra ?? Buffer.alloc(0);
    const declared = fixture.declaredUncompressedSize ?? data.length;
    const local = Buffer.alloc(30 + name.length + localExtra.length + compressed.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(compressionMethod, 8);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(declared, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(localExtra.length, 28);
    name.copy(local, 30);
    localExtra.copy(local, 30 + name.length);
    compressed.copy(local, 30 + name.length + localExtra.length);
    localRecords.push(local);

    const central = Buffer.alloc(46 + name.length + centralExtra.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(((fixture.hostSystem ?? 3) << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(compressionMethod, 10);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(declared, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(centralExtra.length, 30);
    central.writeUInt32LE(((fixture.mode ?? 0o100644) << 16) >>> 0, 38);
    central.writeUInt32LE(fixture.localOffsetOverride ?? localOffset, 42);
    name.copy(central, 46);
    centralExtra.copy(central, 46 + name.length);
    centralRecords.push(central);
    localOffset += local.length;
  }
  const locals = Buffer.concat(localRecords);
  const central = Buffer.concat(centralRecords);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(locals.length, 16);
  return Buffer.concat([locals, central, eocd]);
}

function writeOctal(target: Buffer, offset: number, length: number, value: number): void {
  const encoded = `${value.toString(8).padStart(length - 1, "0")}\0`;
  target.write(encoded, offset, length, "ascii");
}

function makeTarHeader(fixture: TarFixtureEntry): Buffer {
  const header = Buffer.alloc(512);
  if (fixture.nameBytes) fixture.nameBytes.copy(header, 0, 0, 100);
  else header.write(fixture.name, 0, 100, "utf8");
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  const data = Buffer.isBuffer(fixture.data) ? fixture.data : Buffer.from(fixture.data ?? "");
  writeOctal(header, 124, 12, fixture.declaredSize ?? data.length);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header.write(fixture.type ?? "0", 156, 1, "ascii");
  if (fixture.linkBytes) fixture.linkBytes.copy(header, 157, 0, 100);
  else if (fixture.link) header.write(fixture.link, 157, 100, "utf8");
  if (fixture.format === "gnu") {
    header.write("ustar  ", 257, 7, "ascii");
    header[264] = 0;
    writeOctal(header, 345, 12, fixture.gnuAtime ?? 0);
  } else if (fixture.format !== "v7") {
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
  }
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  return header;
}

function makeTar(entries: TarFixtureEntry[], gzip = false): Buffer {
  const records: Buffer[] = [];
  for (const fixture of entries) {
    const data = Buffer.isBuffer(fixture.data) ? fixture.data : Buffer.from(fixture.data ?? "");
    records.push(makeTarHeader(fixture));
    if (!fixture.omitPayload && data.length > 0) {
      records.push(data, Buffer.alloc((512 - (data.length % 512)) % 512));
    }
  }
  records.push(Buffer.alloc(1024));
  const tar = Buffer.concat(records);
  return gzip ? gzipSync(tar) : tar;
}

function paxRecord(key: string, value: string): Buffer {
  const body = `${key}=${value}\n`;
  let length = Buffer.byteLength(body) + 2;
  while (Buffer.byteLength(`${length} ${body}`) !== length) {
    length = Buffer.byteLength(`${length} ${body}`);
  }
  return Buffer.from(`${length} ${body}`);
}

function unicodePathExtra(pathname: string): Buffer {
  const name = Buffer.from(pathname);
  const extra = Buffer.alloc(4 + 5 + name.length);
  extra.writeUInt16LE(0x7075, 0);
  extra.writeUInt16LE(5 + name.length, 2);
  extra[4] = 1;
  name.copy(extra, 9);
  return extra;
}

function asiUnixExtra(mode: number): Buffer {
  const extra = Buffer.alloc(4 + 14);
  extra.writeUInt16LE(0x756e, 0);
  extra.writeUInt16LE(14, 2);
  extra.writeUInt16LE(mode, 8);
  return extra;
}

function xlTypeExtra(mode: number): Buffer {
  const extra = Buffer.alloc(4 + 7);
  extra.writeUInt16LE(0x6c78, 0);
  extra.writeUInt16LE(7, 2);
  extra[4] = 0x05;
  extra.writeUInt16LE((3 << 8) | 20, 5);
  extra.writeUInt32LE((mode << 16) >>> 0, 7);
  return extra;
}

function zip64CountOnly(entryCount: number): Buffer {
  const record = Buffer.alloc(56);
  record.writeUInt32LE(0x06064b50, 0);
  record.writeBigUInt64LE(44n, 4);
  record.writeUInt16LE(45, 12);
  record.writeUInt16LE(45, 14);
  record.writeBigUInt64LE(BigInt(entryCount), 24);
  record.writeBigUInt64LE(BigInt(entryCount), 32);
  const locator = Buffer.alloc(20);
  locator.writeUInt32LE(0x07064b50, 0);
  locator.writeBigUInt64LE(0n, 8);
  locator.writeUInt32LE(1, 16);
  const eocd = Buffer.alloc(22, 0);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0xffff, 8);
  eocd.writeUInt16LE(0xffff, 10);
  eocd.writeUInt32LE(0xffffffff, 12);
  eocd.writeUInt32LE(0xffffffff, 16);
  return Buffer.concat([record, locator, eocd]);
}

describe("archive extraction preflight hardening", () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-archive-preflight-"));
    childProcess.execFileSync.mockReset();
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

  function fixture(name: string, content: Buffer): string {
    const filename = path.join(root, name);
    fs.writeFileSync(filename, content);
    return filename;
  }

  it("preflights valid archives and preserves literal argv-array extraction", () => {
    const zipPath = fixture("payload$(printf injected).vsix", makeZip([
      { name: "./", mode: 0o040755 },
      { name: "payload.txt", data: "safe" },
      { name: "safe/link", data: "../payload.txt", mode: 0o120777 },
    ]));
    const tarPath = fixture("-package;&.tar.gz", makeTar([
      { name: "./", type: "5" },
      { name: "payload.txt", data: "safe" },
      { name: "safe/link", type: "2", link: "../payload.txt" },
      { name: "copy.txt", type: "1", link: "payload.txt" },
    ], true));
    const extractDir = path.join(root, "-extract;&");

    extractZip(zipPath, extractDir, true);
    extractTarGz(tarPath, extractDir);

    const windowsTar = path.win32.join(
      process.env.SystemRoot || "C:\\Windows",
      "System32",
      "tar.exe",
    );
    expect(childProcess.execFileSync).toHaveBeenNthCalledWith(
      1,
      process.platform === "win32" ? windowsTar : "unzip",
      process.platform === "win32"
        ? ["-x", "-f", zipPath, "-C", extractDir]
        : ["-q", "-o", zipPath, "-d", extractDir],
      { stdio: "pipe" },
    );
    expect(childProcess.execFileSync).toHaveBeenNthCalledWith(
      2, "tar", ["xzf", tarPath, "-C", extractDir], { stdio: "pipe" },
    );
  });

  it("keeps existing ZIP files unless overwrite is explicitly enabled", () => {
    const zipPath = fixture("payload.zip", makeZip([{ name: "payload.txt", data: "safe" }]));
    const extractDir = path.join(root, "keep-existing");

    extractZip(zipPath, extractDir);

    if (process.platform === "win32") {
      const windowsTar = path.win32.join(
        process.env.SystemRoot || "C:\\Windows",
        "System32",
        "tar.exe",
      );
      expect(childProcess.execFileSync).toHaveBeenCalledWith(
        windowsTar,
        ["-x", "-k", "-f", zipPath, "-C", extractDir],
        { stdio: "pipe" },
      );
    } else {
      expect(childProcess.execFileSync).toHaveBeenCalledWith(
        "unzip",
        ["-q", zipPath, "-d", extractDir],
        { stdio: "pipe" },
      );
    }
    expect(fs.statSync(extractDir).isDirectory()).toBe(true);
  });

  it("keeps generic tar autodetection on an argv array for PyPI sdists", () => {
    const tarPath = fixture("package.archive", makeTar([{ name: "package/a.py", data: "pass" }]));
    const extractDir = path.join(root, "out");
    extractTar(tarPath, extractDir);
    expect(childProcess.execFileSync).toHaveBeenCalledWith(
      "tar", ["xf", tarPath, "-C", extractDir], { stdio: "pipe" },
    );
  });

  it.each(["../escape", "/absolute", "C:/drive", "dir\\windows-escape"])(
    "rejects unsafe ZIP member path %s before unzip",
    (name) => {
      const archive = fixture("unsafe.zip", makeZip([{ name }]));
      expect(() => extractZip(archive, root)).toThrow(ArchiveSecurityError);
      expect(childProcess.execFileSync).not.toHaveBeenCalled();
    },
  );

  it.each(["../escape", "/absolute", "C:/drive", "dir\\windows-escape"])(
    "rejects unsafe tar member path %s before tar",
    (name) => {
      const archive = fixture("unsafe.tar", makeTar([{ name }]));
      expect(() => extractTar(archive, root)).toThrow(ArchiveSecurityError);
      expect(childProcess.execFileSync).not.toHaveBeenCalled();
    },
  );

  it.each([
    "extension/main.js:payload.js",
    "extension/bad?.js",
    "extension/trailing.",
    "extension/trailing ",
    "extension/NUL.txt",
    "extension/COM\u00b9.log",
    "extension/LONGFI~1.JS",
  ])("rejects non-portable archive member path %s", (name) => {
    const zip = fixture("windows-alias.zip", makeZip([{ name }]));
    const tar = fixture("windows-alias.tar", makeTar([{ name }]));

    expect(() => preflightZipArchive(zip)).toThrow(ArchiveSecurityError);
    expect(() => preflightTarArchive(tar)).toThrow(ArchiveSecurityError);
  });

  it.each([
    ["ASCII case", "Extension/Main.js", "extension/main.js"],
    ["Unicode case", "extension/\u03c3.js", "extension/\u03c2.js"],
  ])("rejects %s member aliases before extraction", (_kind, first, second) => {
    const zip = fixture("case-alias.zip", makeZip([
      { name: first, data: "first" },
      { name: second, data: "second" },
    ]));
    const tar = fixture("case-alias.tar", makeTar([
      { name: "PaxHeader-1", type: "x", data: paxRecord("path", first) },
      { name: "placeholder-1", data: "first" },
      { name: "PaxHeader-2", type: "x", data: paxRecord("path", second) },
      { name: "placeholder-2", data: "second" },
    ]));

    expect(() => preflightZipArchive(zip)).toThrow(/case-aliased/);
    expect(() => preflightTarArchive(tar)).toThrow(/case-aliased/);
  });

  it("rejects HFS-ignorable member aliases before ZIP or tar extraction", () => {
    for (const ignorable of ["\u200c", "\u202e", "\u206a", "\ufeff", "\ufe0f"]) {
      const first = "extension/payload.js";
      const second = `extension/pay${ignorable}load.js`;
      const zip = fixture("hfs-alias.zip", makeZip([
        { name: first, data: "first" },
        { name: second, data: "second" },
      ]));
      const tar = fixture("hfs-alias.tar", makeTar([
        { name: "PaxHeader-1", type: "x", data: paxRecord("path", first) },
        { name: "placeholder-1", data: "first" },
        { name: "PaxHeader-2", type: "x", data: paxRecord("path", second) },
        { name: "placeholder-2", data: "second" },
      ]));

      expect(() => preflightZipArchive(zip)).toThrow(/default-ignorable/);
      expect(() => preflightTarArchive(tar)).toThrow(/default-ignorable/);
    }
  });

  it("rejects mixed legacy and UTF-8 ZIP names that extract to one path", () => {
    const legacyName = Buffer.concat([
      Buffer.from("extension/"),
      Buffer.from([0xc3, 0xa9]),
      Buffer.from(".js"),
    ]);
    const zip = fixture("legacy-alias.zip", makeZip([
      { name: "unused", nameBytes: legacyName, flags: 0, data: "legacy" },
      { name: "extension/\u251c\u2310.js", data: "utf8" },
    ]));

    expect(() => preflightZipArchive(zip)).toThrow(/legacy-encoded.*ASCII/);
  });

  it("rejects non-ASCII targets in legacy-encoded ZIP symlinks", () => {
    const zip = fixture("legacy-link.zip", makeZip([{
      name: "extension/link",
      flags: 0,
      mode: 0o120777,
      data: Buffer.from([0xc3, 0xa9]),
    }]));

    expect(() => preflightZipArchive(zip)).toThrow(/legacy-encoded ZIP link.*ASCII/);
  });

  it("rejects raw tar names whose OEM decoding can case-alias on Windows", () => {
    const prefix = Buffer.from("extension/pay");
    const suffix = Buffer.from(".js");
    const first = Buffer.concat([prefix, Buffer.from([0xc2, 0x81]), suffix]);
    const second = Buffer.concat([prefix, Buffer.from([0xc2, 0x9a]), suffix]);
    const tar = fixture("legacy-tar-alias.tar", makeTar([
      { name: "unused-1", nameBytes: first, data: "first" },
      { name: "unused-2", nameBytes: second, data: "second" },
    ]));

    expect(() => preflightTarArchive(tar)).toThrow(/tar header name must be ASCII/);
  });

  it("rejects non-ASCII legacy tar link fields and GNU long-name records", () => {
    const rawLink = fixture("legacy-tar-link.tar", makeTar([{
      name: "link",
      type: "2",
      linkBytes: Buffer.from([0xc3, 0xa9]),
    }]));
    const gnuLongName = fixture("legacy-gnu-long-name.tar", makeTar([
      { name: "././@LongLink", type: "L", data: Buffer.from([0xc3, 0xa9, 0]) },
      { name: "placeholder", data: "payload" },
    ]));

    expect(() => preflightTarArchive(rawLink)).toThrow(/tar header link target must be ASCII/);
    expect(() => preflightTarArchive(gnuLongName)).toThrow(/GNU tar long-name record must be ASCII/);
  });

  it("allows Unicode PAX paths even when the metadata header placeholder is non-ASCII", () => {
    const unicodePath = "extension/\u00e9.js";
    const tar = fixture("unicode-pax.tar", makeTar([
      {
        name: "unused-pax-header",
        nameBytes: Buffer.from("PaxHeader/\u00e9.js"),
        type: "x",
        data: paxRecord("path", unicodePath),
      },
      { name: "placeholder", data: "payload" },
    ]));

    expect(() => preflightTarArchive(tar)).not.toThrow();
  });

  it("rejects oversized or excessively deep PAX paths before graph validation", () => {
    const cases = [
      ["oversized-pax.tar.gz", `${"a/".repeat(8_193)}payload.js`, /PAX path exceeds/],
      [
        "deep-pax.tar.gz",
        `${Array.from({ length: ARCHIVE_MAX_PATH_COMPONENTS + 1 }, () => "a").join("/")}/payload.js`,
        /path components/,
      ],
    ] as const;

    for (const [name, memberPath, expected] of cases) {
      const archive = fixture(name, makeTar([
        { name: "PaxHeader", type: "x", data: paxRecord("path", memberPath) },
        { name: "placeholder", data: "payload" },
      ], true));
      const started = performance.now();
      expect(() => preflightTarArchive(archive)).toThrow(expected);
      expect(performance.now() - started).toBeLessThan(250);
    }
  });

  it("charges aggregate prefix work for many maximum-depth PAX paths", () => {
    const prefix = Array.from(
      { length: ARCHIVE_MAX_PATH_COMPONENTS - 1 },
      () => "d",
    ).join("/");
    const entries: TarFixtureEntry[] = [];
    for (let index = 0; index < 800; index++) {
      entries.push(
        { name: `PaxHeader-${index}`, type: "x", data: paxRecord("path", `${prefix}/${index}`) },
        { name: `placeholder-${index}` },
      );
    }
    const archive = fixture("aggregate-pax-work.tar.gz", makeTar(entries, true));

    expect(() => preflightTarArchive(archive)).toThrow(/resolution work exceeds/);
  });

  it("uses stream order when PAX and GNU path overrides are mixed", () => {
    const paxThenGnu = fixture("pax-then-gnu.tar", makeTar([
      { name: "PaxHeader", type: "x", data: paxRecord("path", "../discarded") },
      { name: "././@LongLink", type: "L", data: "safe.txt\0" },
      { name: "placeholder", data: "payload" },
    ]));
    const gnuThenPax = fixture("gnu-then-pax.tar", makeTar([
      { name: "././@LongLink", type: "L", data: "safe.txt\0" },
      { name: "PaxHeader", type: "x", data: paxRecord("path", "../selected") },
      { name: "placeholder", data: "payload" },
    ]));

    expect(() => preflightTarArchive(paxThenGnu)).not.toThrow();
    expect(() => preflightTarArchive(gnuThenPax)).toThrow(/traverses outside/);
  });

  it("uses stream order when PAX and GNU link overrides are mixed", () => {
    const paxThenGnu = fixture("pax-then-gnu-link.tar", makeTar([
      { name: "PaxHeader", type: "x", data: paxRecord("linkpath", "../discarded") },
      { name: "././@LongLink", type: "K", data: "safe-target\0" },
      { name: "link", type: "2" },
    ]));
    const gnuThenPax = fixture("gnu-then-pax-link.tar", makeTar([
      { name: "././@LongLink", type: "K", data: "safe-target\0" },
      { name: "PaxHeader", type: "x", data: paxRecord("linkpath", "../selected") },
      { name: "link", type: "2" },
    ]));

    expect(() => preflightTarArchive(paxThenGnu)).not.toThrow();
    expect(() => preflightTarArchive(gnuThenPax)).toThrow(/escapes the extraction root/);
  });

  it("merges consecutive per-file PAX records with later keys winning", () => {
    const tar = fixture("merged-pax.tar", makeTar([
      { name: "PaxHeader-1", type: "x", data: paxRecord("path", "../selected") },
      { name: "PaxHeader-2", type: "x", data: paxRecord("size", "0") },
      { name: "placeholder" },
    ]));

    expect(() => preflightTarArchive(tar)).toThrow(/traverses outside/);
  });

  it("does not interpret old-GNU timestamp bytes as a POSIX pathname prefix", () => {
    const tar = fixture("old-gnu-prefix-alias.tar", makeTar([
      { name: "payload", format: "gnu", gnuAtime: 1, data: "first" },
      { name: "payload", data: "second" },
    ]));

    expect(() => preflightTarArchive(tar)).toThrow(/duplicate or case-aliased/);
  });

  it("rejects non-portable syntax in link targets", () => {
    const zip = fixture("link-alias.zip", makeZip([
      { name: "link", data: "payload:stream", mode: 0o120777 },
    ]));
    const tar = fixture("link-alias.tar", makeTar([
      { name: "link", type: "2", link: "payload:stream" },
    ]));

    expect(() => preflightZipArchive(zip)).toThrow(/Windows-special/);
    expect(() => preflightTarArchive(tar)).toThrow(/Windows-special/);
  });

  it("rejects unsafe ZIP and tar links, including symlink-then-child structures", () => {
    const zip = fixture("link.zip", makeZip([
      { name: "pivot", data: "../outside", mode: 0o120777 },
      { name: "pivot/payload", data: "bad" },
    ]));
    const tar = fixture("link.tar", makeTar([
      { name: "pivot", type: "2", link: "../outside" },
      { name: "pivot/payload", data: "bad" },
    ]));
    expect(() => preflightZipArchive(zip)).toThrow(/link .* escapes/);
    expect(() => preflightTarArchive(tar)).toThrow(/link .* escapes/);
  });

  it("memoizes a long contained symlink chain across graph validation", () => {
    const linkCount = 2_500;
    const entries: TarFixtureEntry[] = Array.from(
      { length: linkCount },
      (_, index) => ({
        name: `link-${String(index).padStart(4, "0")}`,
        type: "2",
        link: index + 1 === linkCount
          ? "payload"
          : `link-${String(index + 1).padStart(4, "0")}`,
      }),
    );
    entries.push({ name: "payload", data: "safe" });
    const archive = fixture("long-link-chain.tar", makeTar(entries));

    expect(() => preflightTarArchive(archive)).not.toThrow();
  }, 20_000);

  it("rejects a link cycle whose remaining suffix grows on every pass", () => {
    const archive = fixture("expanding-link-cycle.tar", makeTar([
      { name: "a", type: "2", link: "b/x" },
      { name: "b", type: "2", link: "a/y" },
    ]));

    expect(() => preflightTarArchive(archive)).toThrow(/link cycle passes through/);
  });

  it("rejects unsafe hardlinks but preserves contained hardlinks", () => {
    const missing = fixture("missing.tar", makeTar([{ name: "alias", type: "1", link: "missing" }]));
    const traversal = fixture("traversal.tar", makeTar([{ name: "alias", type: "1", link: "../outside" }]));
    const valid = fixture("valid.tar", makeTar([
      { name: "payload", data: "safe" },
      { name: "alias", type: "1", link: "payload" },
    ]));
    expect(() => preflightTarArchive(missing)).toThrow(/does not target a regular/);
    expect(() => preflightTarArchive(traversal)).toThrow(/traverses outside/);
    expect(() => preflightTarArchive(valid)).not.toThrow();
  });

  it("rejects special filesystem nodes in ZIP and tar archives", () => {
    const zip = fixture("special.zip", makeZip([{ name: "device", mode: 0o020666 }]));
    const tar = fixture("special.tar", makeTar([{ name: "device", type: "3" }]));
    expect(() => preflightZipArchive(zip)).toThrow(/special filesystem node/);
    expect(() => preflightTarArchive(tar)).toThrow(/special filesystem node/);
  });

  it("rejects a deflate stream that expands beyond its attacker-declared size", () => {
    const archive = fixture("lying-bomb.zip", makeZip([{
      name: "bomb",
      data: Buffer.alloc(1024 * 1024, 0x61),
      compressionMethod: 8,
      declaredUncompressedSize: 16,
    }]));
    expect(() => preflightZipArchive(archive)).toThrow(ArchiveSecurityError);
    expect(childProcess.execFileSync).not.toHaveBeenCalled();
  });

  it("rejects excessive declared expansion before extraction", () => {
    const tooLarge = ARCHIVE_MAX_EXPANDED_BYTES + 1;
    const zip = fixture("bomb.zip", makeZip([{ name: "bomb", declaredUncompressedSize: tooLarge }]));
    const tar = fixture("bomb.tar", makeTar([{ name: "bomb", declaredSize: tooLarge, omitPayload: true }]));
    expect(() => preflightZipArchive(zip)).toThrow(/expanded size exceeds/);
    expect(() => preflightTarArchive(tar)).toThrow(/expanded size exceeds/);
  });

  it("rejects a ZIP entry count beyond the global extraction budget", () => {
    const archive = fixture("many.zip", zip64CountOnly(ARCHIVE_MAX_ENTRIES + 1));
    expect(() => preflightZipArchive(archive)).toThrow(/entry count exceeds/);
  });

  it("rejects a tar entry count beyond the global extraction budget", () => {
    const header = makeTarHeader({ name: "same" });
    const content = Buffer.allocUnsafe((ARCHIVE_MAX_ENTRIES + 1) * 512 + 1024);
    for (let index = 0; index <= ARCHIVE_MAX_ENTRIES; index++) header.copy(content, index * 512);
    content.fill(0, (ARCHIVE_MAX_ENTRIES + 1) * 512);
    const archive = fixture("many.tar", content);
    expect(() => preflightTarArchive(archive)).toThrow(/entry count exceeds/);
  }, 20_000);

  it("rejects path-overriding Unicode extras and overlapping local ZIP regions", () => {
    const unicode = fixture("unicode.zip", makeZip([
      { name: "safe", centralExtra: unicodePathExtra("../escape") },
    ]));
    const localUnicode = fixture("local-unicode.zip", makeZip([
      { name: "safe", localExtra: unicodePathExtra("../escape") },
    ]));
    const overlap = fixture("overlap.zip", makeZip([
      { name: "same", data: "x" },
      { name: "same", data: "x", localOffsetOverride: 0 },
    ]));
    expect(() => preflightZipArchive(unicode)).toThrow(/path-overriding Unicode/);
    expect(() => preflightZipArchive(localUnicode)).toThrow(/path-overriding Unicode/);
    expect(() => preflightZipArchive(overlap)).toThrow(/overlap/);
  });

  it("rejects ASi Unix extra fields that can override a ZIP member type", () => {
    const archive = fixture("asi-symlink.zip", makeZip([{
      name: "looks-like-a-file",
      mode: 0,
      centralExtra: asiUnixExtra(0o120777),
      data: "../outside",
    }]));

    expect(() => preflightZipArchive(archive)).toThrow(/ASi Unix type-overriding/);
  });

  it("rejects local or central xl fields that can override a ZIP member type", () => {
    const local = fixture("local-xl-symlink.zip", makeZip([{
      name: "looks-like-a-file",
      mode: 0o100644,
      localExtra: xlTypeExtra(0o120777),
      data: "../outside",
    }]));
    const central = fixture("central-xl-symlink.zip", makeZip([{
      name: "looks-like-a-file",
      mode: 0o100644,
      centralExtra: xlTypeExtra(0o120777),
      data: "../outside",
    }]));

    expect(() => preflightZipArchive(local)).toThrow(/xl type-overriding/);
    expect(() => preflightZipArchive(central)).toThrow(/xl type-overriding/);
  });

  it("rejects Unix type bits from non-Unix ZIP hosts", () => {
    const archive = fixture("foreign-host-symlink.zip", makeZip([{
      name: "looks-like-a-file",
      hostSystem: 5,
      mode: 0o120777,
      data: "../outside",
    }]));

    expect(() => preflightZipArchive(archive)).toThrow(/ambiguous Unix type bits/);
  });

  it("rejects malformed archive structure before invoking an extractor", () => {
    const zip = fixture("tree.zip", makeZip([
      { name: "parent", data: "file" },
      { name: "parent/child", data: "file" },
    ]));
    const tar = fixture("tree.tar", makeTar([
      { name: "parent", data: "file" },
      { name: "parent/child", data: "file" },
    ]));
    expect(() => extractZip(zip, root)).toThrow(/nested below non-directory/);
    expect(() => extractTar(tar, root)).toThrow(/nested below non-directory/);
    expect(childProcess.execFileSync).not.toHaveBeenCalled();
  });

  it("keeps production archive scanners free of shell-string execution", () => {
    const sourceRoot = path.resolve(__dirname, "..");
    for (const filename of ["vscode-scanner.ts", "npm-scanner.ts", "pypi-scanner.ts"]) {
      const source = fs.readFileSync(path.join(sourceRoot, filename), "utf8");
      expect(source).not.toMatch(/\bexecSync\b/);
    }
  });
});
