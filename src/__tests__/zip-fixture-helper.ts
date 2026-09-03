import { crc32, deflateRawSync } from "node:zlib";

export type ZipFixtureEntry = {
  name: string;
  nameBytes?: Buffer;
  flags?: number;
  hostSystem?: number;
  data?: Buffer | string;
  crc?: number;
  mode?: number;
  centralExtra?: Buffer;
  localExtra?: Buffer;
  declaredUncompressedSize?: number;
  compressionMethod?: 0 | 8;
  localOffsetOverride?: number;
};

export function makeZip(entries: ZipFixtureEntry[]): Buffer {
  const localRecords: Buffer[] = [];
  const centralRecords: Buffer[] = [];
  let localOffset = 0;
  for (const fixture of entries) {
    const name = fixture.nameBytes ?? Buffer.from(fixture.name);
    const flags = fixture.flags ?? 0x0800;
    const data = Buffer.isBuffer(fixture.data) ? fixture.data : Buffer.from(fixture.data ?? "");
    const compressionMethod = fixture.compressionMethod ?? 0;
    const compressed = compressionMethod === 8 ? deflateRawSync(data) : data;
    const fileCrc = fixture.crc !== undefined ? fixture.crc : crc32(data);
    const localExtra = fixture.localExtra ?? Buffer.alloc(0);
    const centralExtra = fixture.centralExtra ?? Buffer.alloc(0);
    const declared = fixture.declaredUncompressedSize ?? data.length;
    const local = Buffer.alloc(30 + name.length + localExtra.length + compressed.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(compressionMethod, 8);
    local.writeUInt32LE(fileCrc, 14);
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
    central.writeUInt32LE(fileCrc, 16);
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

/**
 * Convenience helper to build a zip archive directly from a map of relative paths and contents.
 */
export function buildZipFromMap(files: Record<string, string | Buffer>): Buffer {
  const entries: ZipFixtureEntry[] = Object.entries(files).map(([name, content]) => ({
    name: name.replace(/\\/g, "/"),
    data: content,
  }));
  return makeZip(entries);
}
