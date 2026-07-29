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
  ArchiveSecurityError,
  extractTar,
  extractTarGz,
  extractZip,
  preflightTarArchive,
  preflightZipArchive,
} from "../archive-extractor.js";

type ZipFixtureEntry = {
  name: string;
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
  type?: string;
  data?: Buffer | string;
  link?: string;
  declaredSize?: number;
  omitPayload?: boolean;
};

function makeZip(entries: ZipFixtureEntry[]): Buffer {
  const localRecords: Buffer[] = [];
  const centralRecords: Buffer[] = [];
  let localOffset = 0;
  for (const fixture of entries) {
    const name = Buffer.from(fixture.name);
    const data = Buffer.isBuffer(fixture.data) ? fixture.data : Buffer.from(fixture.data ?? "");
    const compressionMethod = fixture.compressionMethod ?? 0;
    const compressed = compressionMethod === 8 ? deflateRawSync(data) : data;
    const localExtra = fixture.localExtra ?? Buffer.alloc(0);
    const centralExtra = fixture.centralExtra ?? Buffer.alloc(0);
    const declared = fixture.declaredUncompressedSize ?? data.length;
    const local = Buffer.alloc(30 + name.length + localExtra.length + compressed.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
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
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
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
  header.write(fixture.name, 0, 100, "utf8");
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  const data = Buffer.isBuffer(fixture.data) ? fixture.data : Buffer.from(fixture.data ?? "");
  writeOctal(header, 124, 12, fixture.declaredSize ?? data.length);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header.write(fixture.type ?? "0", 156, 1, "ascii");
  if (fixture.link) header.write(fixture.link, 157, 100, "utf8");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
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

function unicodePathExtra(pathname: string): Buffer {
  const name = Buffer.from(pathname);
  const extra = Buffer.alloc(4 + 5 + name.length);
  extra.writeUInt16LE(0x7075, 0);
  extra.writeUInt16LE(5 + name.length, 2);
  extra[4] = 1;
  name.copy(extra, 9);
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

    expect(childProcess.execFileSync).toHaveBeenNthCalledWith(
      1, "unzip", ["-q", "-o", zipPath, "-d", extractDir], { stdio: "pipe" },
    );
    expect(childProcess.execFileSync).toHaveBeenNthCalledWith(
      2, "tar", ["xzf", tarPath, "-C", extractDir], { stdio: "pipe" },
    );
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
