/**
 * Archive extraction helpers. Every member is validated before an argv-array
 * extractor invocation so an archive cannot write outside the extraction root.
 */

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { gunzipSync, inflateRawSync } from "node:zlib";

export const ARCHIVE_MAX_ENTRIES = 100_000;
export const ARCHIVE_MAX_INPUT_BYTES = 128 * 1024 * 1024;
export const ARCHIVE_MAX_EXPANDED_BYTES = 256 * 1024 * 1024;
export const ARCHIVE_MAX_PATH_COMPONENTS = 64;

const MAX_LINK_TARGET_BYTES = 16 * 1024;
const ZIP_EOCD_MIN_SIZE = 22;
const ZIP_EOCD_MAX_SEARCH = ZIP_EOCD_MIN_SIZE + 0xffff;
const ZIP_CENTRAL_HEADER_SIZE = 46;
const ZIP_LOCAL_HEADER_SIZE = 30;
const TAR_BLOCK_SIZE = 512;
const ARCHIVE_MAX_RESOLUTION_WORK = ARCHIVE_MAX_ENTRIES * 16;
const WINDOWS_FORBIDDEN_COMPONENT_CHARS = /[<>:"|?*\u0001-\u001f]/u;
const WINDOWS_RESERVED_COMPONENT =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/iu;
const WINDOWS_SHORT_NAME_ALIAS = /~[1-9][0-9]*(?:\.|$)/u;
const UNICODE_DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;

type ArchiveEntryKind = "file" | "directory" | "symlink" | "hardlink";
interface ArchiveEntry { path: string; kind: ArchiveEntryKind; target?: string }
interface ZipEntry extends ArchiveEntry {
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  flags: number;
  crc32: number;
  localHeaderOffset: number;
  filenameBytes: Buffer;
}
interface TarOverrides { path?: string; linkpath?: string; size?: number; sparse?: boolean }
interface ArchiveResolutionContext {
  resolvedPaths: Map<string, string>;
  work: number;
}

export class ArchiveSecurityError extends Error {
  constructor(message: string) {
    super(`Unsafe archive: ${message}`);
    this.name = "ArchiveSecurityError";
  }
}

function unsafe(message: string): never { throw new ArchiveSecurityError(message); }

function checkedSafeInteger(value: bigint, label: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    unsafe(`${label} is outside the supported range`);
  }
  return Number(value);
}

function addExpandedBytes(total: number, value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) unsafe("an entry has an invalid declared size");
  const next = total + value;
  if (!Number.isSafeInteger(next) || next > ARCHIVE_MAX_EXPANDED_BYTES) {
    unsafe(`declared expanded size exceeds ${ARCHIVE_MAX_EXPANDED_BYTES} bytes`);
  }
  return next;
}

function readBoundedArchive(archivePath: string): Buffer {
  let stat: fs.Stats;
  try { stat = fs.statSync(archivePath); }
  catch { unsafe("the archive cannot be inspected"); }
  if (!stat.isFile()) unsafe("the archive is not a regular file");
  if (stat.size > ARCHIVE_MAX_INPUT_BYTES) unsafe(`input size exceeds ${ARCHIVE_MAX_INPUT_BYTES} bytes`);
  const content = fs.readFileSync(archivePath);
  if (content.length > ARCHIVE_MAX_INPUT_BYTES) unsafe(`input size exceeds ${ARCHIVE_MAX_INPUT_BYTES} bytes`);
  return content;
}

/**
 * Reject member components whose on-disk identity can differ across supported
 * extractors. Windows bsdtar sanitizes reserved punctuation, Win32 trims final
 * dots/spaces, DOS device names bypass ordinary filename semantics, 8.3 aliases
 * can collide with a different long name, and case-insensitive HFS+ ignores
 * Unicode formatting code points during comparison. Reject the full Unicode
 * Default_Ignorable set rather than maintaining an incomplete HFS-era subset.
 * A partial scan is safer than validating one name and scanning bytes extracted
 * under another.
 */
function validatePortableMemberComponent(component: string, label: string): void {
  if (WINDOWS_FORBIDDEN_COMPONENT_CHARS.test(component)) {
    unsafe(`${label} contains Windows-special filename syntax`);
  }
  if (/[. ]$/u.test(component)) {
    unsafe(`${label} ends with a dot or space`);
  }
  if (WINDOWS_RESERVED_COMPONENT.test(component)) {
    unsafe(`${label} uses a reserved Windows device name`);
  }
  if (WINDOWS_SHORT_NAME_ALIAS.test(component)) {
    unsafe(`${label} can alias a Windows 8.3 short name`);
  }
  if (UNICODE_DEFAULT_IGNORABLE.test(component)) {
    unsafe(`${label} contains a Unicode default-ignorable filename character`);
  }
}

/** Key paths the way the case-insensitive Windows extraction backend sees them. */
function portableMemberPathKey(memberPath: string): string {
  return memberPath
    .split("/")
    // Windows compares filenames through an invariant uppercase table. Using
    // lowercase misses aliases such as Greek sigma/final-sigma and long-s.
    .map((component) =>
      component.normalize("NFC").toUpperCase().normalize("NFC")
    )
    .join("/");
}

/** Normalize using POSIX semantics; reject host-dependent backslash handling. */
function normalizeMemberPath(rawPath: string, label = "entry path", allowRoot = false): string {
  if (rawPath.length === 0 || rawPath.includes("\0")) unsafe(`${label} is empty or contains NUL`);
  if (Buffer.byteLength(rawPath, "utf8") > MAX_LINK_TARGET_BYTES) {
    unsafe(`${label} exceeds ${MAX_LINK_TARGET_BYTES} bytes`);
  }
  if (rawPath.includes("\\")) unsafe(`${label} contains a backslash`);
  if (rawPath.startsWith("/") || /^[A-Za-z]:/.test(rawPath)) unsafe(`${label} is absolute`);
  const normalized: string[] = [];
  for (const component of rawPath.split("/")) {
    if (component === "" || component === ".") continue;
    if (component === "..") unsafe(`${label} traverses outside the extraction root`);
    validatePortableMemberComponent(component, label);
    normalized.push(component);
    if (normalized.length > ARCHIVE_MAX_PATH_COMPONENTS) {
      unsafe(`${label} exceeds ${ARCHIVE_MAX_PATH_COMPONENTS} path components`);
    }
  }
  if (normalized.length === 0 && !allowRoot) unsafe(`${label} does not name an archive member`);
  return normalized.join("/");
}

function resolveRelativeTarget(linkPath: string, rawTarget: string): string {
  if (rawTarget.length === 0 || rawTarget.includes("\0")) unsafe(`link "${linkPath}" has an empty or NUL-containing target`);
  if (Buffer.byteLength(rawTarget, "utf8") > MAX_LINK_TARGET_BYTES) {
    unsafe(`link "${linkPath}" target exceeds ${MAX_LINK_TARGET_BYTES} bytes`);
  }
  if (rawTarget.includes("\\")) unsafe(`link "${linkPath}" has a backslash-containing target`);
  if (rawTarget.startsWith("/") || /^[A-Za-z]:/.test(rawTarget)) unsafe(`link "${linkPath}" has an absolute target`);
  const components = linkPath.split("/");
  components.pop();
  for (const component of rawTarget.split("/")) {
    if (component === "" || component === ".") continue;
    if (component === "..") {
      if (components.length === 0) unsafe(`link "${linkPath}" escapes the extraction root`);
      components.pop();
    } else {
      validatePortableMemberComponent(component, `link "${linkPath}" target`);
      components.push(component);
      if (components.length > ARCHIVE_MAX_PATH_COMPONENTS) {
        unsafe(`link "${linkPath}" target exceeds ${ARCHIVE_MAX_PATH_COMPONENTS} path components`);
      }
    }
  }

  return components.join("/");
}

function resolveHardlinkTarget(linkPath: string, rawTarget: string): string {
  return normalizeMemberPath(rawTarget, `hardlink "${linkPath}" target`);
}

function chargeResolutionWork(context: ArchiveResolutionContext, amount: number): void {
  context.work += amount;
  if (context.work > ARCHIVE_MAX_RESOLUTION_WORK) {
    unsafe(`link resolution work exceeds ${ARCHIVE_MAX_RESOLUTION_WORK} component checks`);
  }
}

/** Resolve the archive's virtual links, including symlink-then-child writes. */
function resolveVirtualPath(
  rawPath: string,
  entries: ReadonlyMap<string, ArchiveEntry>,
  followFinal: boolean,
  context: ArchiveResolutionContext,
): string {
  let components = rawPath === "" ? [] : rawPath.split("/");
  const visitedLinks = new Set<string>();
  const cacheTrail: string[] = [];

  for (let hops = 0; hops <= ARCHIVE_MAX_ENTRIES; hops++) {
    const currentPath = components.join("/");
    const cacheKey =
      `${followFinal ? "follow" : "preserve"}\0${portableMemberPathKey(currentPath)}`;
    const cached = context.resolvedPaths.get(cacheKey);
    if (cached !== undefined) {
      for (const trailKey of cacheTrail) context.resolvedPaths.set(trailKey, cached);
      return cached;
    }
    cacheTrail.push(cacheKey);

    let replaced = false;
    const prefix: string[] = [];
    for (let index = 0; index < components.length; index++) {
      // Building and normalizing this prefix costs index + 1 component visits,
      // not one. Charging the real unit prevents many medium-depth paths from
      // bypassing the work budget after a single deep path is capped.
      chargeResolutionWork(context, index + 1);

      prefix.push(components[index]!);
      const current = prefix.join("/");
      const currentKey = portableMemberPathKey(current);
      const entry = entries.get(currentKey);
      const isFinal = index === components.length - 1;
      if (entry?.kind !== "symlink" || (isFinal && !followFinal)) continue;
      // Seeing the same link twice while resolving one path is a cycle even
      // when each pass grows or otherwise changes the remaining suffix.
      if (visitedLinks.has(currentKey)) unsafe(`link cycle passes through "${current}"`);
      visitedLinks.add(currentKey);
      if (entry.target === undefined) unsafe(`link "${current}" has no target`);
      const targetComponents = entry.target === "" ? [] : entry.target.split("/");
      components = [...targetComponents, ...components.slice(index + 1)];
      replaced = true;
      break;
    }
    if (!replaced) {
      const resolved = components.join("/");
      for (const trailKey of cacheTrail) context.resolvedPaths.set(trailKey, resolved);
      return resolved;
    }
  }
  unsafe(`link resolution exceeds ${ARCHIVE_MAX_ENTRIES} hops`);
}

function validateArchiveGraph(entries: ArchiveEntry[]): void {
  const byPath = new Map<string, ArchiveEntry>();
  for (const entry of entries) {
    const entryKey = portableMemberPathKey(entry.path);
    if (byPath.has(entryKey)) {
      unsafe(`duplicate or case-aliased member path "${entry.path}"`);
    }
    byPath.set(entryKey, entry);
  }
  const resolutionContext: ArchiveResolutionContext = {
    resolvedPaths: new Map(),
    work: 0,
  };
  for (const entry of entries) {
    const components = entry.path.split("/");
    for (let length = 1; length < components.length; length++) {
      chargeResolutionWork(resolutionContext, length);
      const ancestorPath = components.slice(0, length).join("/");
      const ancestor = byPath.get(portableMemberPathKey(ancestorPath));
      if (ancestor !== undefined && ancestor.kind !== "directory" && ancestor.kind !== "symlink") {
        unsafe(`member "${entry.path}" is nested below non-directory "${ancestorPath}"`);
      }
    }
    const parent = components.slice(0, -1).join("/");
    if (parent.length > 0) resolveVirtualPath(parent, byPath, true, resolutionContext);
    if (entry.kind === "symlink") resolveVirtualPath(entry.path, byPath, true, resolutionContext);
  }
  for (const entry of entries) {
    if (entry.kind !== "hardlink") continue;
    if (entry.target === undefined) unsafe(`hardlink "${entry.path}" has no target`);
    const resolved = resolveVirtualPath(entry.target, byPath, true, resolutionContext);
    const targetEntry = byPath.get(portableMemberPathKey(resolved));
    if (targetEntry === undefined || targetEntry.kind !== "file") {
      unsafe(`hardlink "${entry.path}" does not target a regular archive member`);
    }
  }
}

function findZipEndOfCentralDirectory(content: Buffer): number {
  const first = Math.max(0, content.length - ZIP_EOCD_MAX_SEARCH);
  for (let offset = content.length - ZIP_EOCD_MIN_SIZE; offset >= first; offset--) {
    if (content.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = content.readUInt16LE(offset + 20);
    if (offset + ZIP_EOCD_MIN_SIZE + commentLength === content.length) return offset;
  }
  unsafe("ZIP end-of-central-directory record is missing or malformed");
}

function validateZipExtraFields(extra: Buffer, label: string): void {
  let cursor = 0;
  while (cursor < extra.length) {
    if (cursor + 4 > extra.length) unsafe(`${label} extra field is truncated`);
    const id = extra.readUInt16LE(cursor);
    const size = extra.readUInt16LE(cursor + 2);
    cursor += 4;
    if (cursor + size > extra.length) unsafe(`${label} extra field is truncated`);
    // Info-ZIP's Unicode Path field can override the header filename. Reject it
    // so unzip cannot extract a path other than the one validated here.
    if (id === 0x7075) unsafe(`${label} contains a path-overriding Unicode extra field`);
    // Info-ZIP's ASi Unix field can override the central Unix mode, including
    // changing a preflighted regular file into a symlink during extraction.
    if (id === 0x756e) unsafe(`${label} contains an ASi Unix type-overriding extra field`);
    // Libarchive's experimental xl field can copy made-by and external mode
    // attributes into a local header, changing the entry type after the central
    // directory was preflighted.
    if (id === 0x6c78) unsafe(`${label} contains an xl type-overriding extra field`);
    cursor += size;
  }
}
function parseZip64Extra(extra: Buffer, needUncompressed: boolean, needCompressed: boolean, needOffset: boolean): {
  uncompressedSize?: number; compressedSize?: number; localOffset?: number;
} {
  if (!needUncompressed && !needCompressed && !needOffset) return {};
  let cursor = 0;
  while (cursor + 4 <= extra.length) {
    const id = extra.readUInt16LE(cursor);
    const size = extra.readUInt16LE(cursor + 2);
    cursor += 4;
    if (cursor + size > extra.length) unsafe("ZIP extra field is truncated");
    if (id !== 0x0001) { cursor += size; continue; }
    const end = cursor + size;
    const result: { uncompressedSize?: number; compressedSize?: number; localOffset?: number } = {};
    const readValue = (label: string): number => {
      if (cursor + 8 > end) unsafe(`ZIP64 ${label} is truncated`);
      const value = checkedSafeInteger(extra.readBigUInt64LE(cursor), `ZIP64 ${label}`);
      cursor += 8;
      return value;
    };
    if (needUncompressed) result.uncompressedSize = readValue("uncompressed size");
    if (needCompressed) result.compressedSize = readValue("compressed size");
    if (needOffset) result.localOffset = readValue("local-header offset");
    return result;
  }
  unsafe("ZIP64 sentinel is present without a ZIP64 extra field");
}

function parseZipDirectoryLocation(content: Buffer, eocdOffset: number): {
  entryCount: number; centralSize: number; centralOffset: number;
} {
  const disk = content.readUInt16LE(eocdOffset + 4);
  const centralDisk = content.readUInt16LE(eocdOffset + 6);
  const entriesOnDisk = content.readUInt16LE(eocdOffset + 8);
  const entryCount16 = content.readUInt16LE(eocdOffset + 10);
  const centralSize32 = content.readUInt32LE(eocdOffset + 12);
  const centralOffset32 = content.readUInt32LE(eocdOffset + 16);
  if (disk !== 0 || centralDisk !== 0 || entriesOnDisk !== entryCount16) unsafe("multi-disk ZIP archives are not supported");
  const needsZip64 = entryCount16 === 0xffff || centralSize32 === 0xffffffff || centralOffset32 === 0xffffffff;
  if (!needsZip64) return { entryCount: entryCount16, centralSize: centralSize32, centralOffset: centralOffset32 };
  const locatorOffset = eocdOffset - 20;
  if (locatorOffset < 0 || content.readUInt32LE(locatorOffset) !== 0x07064b50) unsafe("ZIP64 locator is missing");
  if (content.readUInt32LE(locatorOffset + 4) !== 0 || content.readUInt32LE(locatorOffset + 16) !== 1) unsafe("multi-disk ZIP64 archives are not supported");
  const recordOffset = checkedSafeInteger(content.readBigUInt64LE(locatorOffset + 8), "ZIP64 directory offset");
  if (recordOffset + 56 > locatorOffset || content.readUInt32LE(recordOffset) !== 0x06064b50) unsafe("ZIP64 end-of-central-directory record is malformed");
  const recordSize = checkedSafeInteger(content.readBigUInt64LE(recordOffset + 4), "ZIP64 record size");
  if (recordOffset + 12 + recordSize !== locatorOffset) unsafe("ZIP64 end-of-central-directory size is inconsistent");
  if (content.readUInt32LE(recordOffset + 16) !== 0 || content.readUInt32LE(recordOffset + 20) !== 0) unsafe("multi-disk ZIP64 archives are not supported");
  const entriesOnZip64Disk = content.readBigUInt64LE(recordOffset + 24);
  const zip64EntryCount = content.readBigUInt64LE(recordOffset + 32);
  if (entriesOnZip64Disk !== zip64EntryCount) unsafe("multi-disk ZIP64 archives are not supported");
  return {
    entryCount: checkedSafeInteger(zip64EntryCount, "ZIP64 entry count"),
    centralSize: checkedSafeInteger(content.readBigUInt64LE(recordOffset + 40), "ZIP64 central-directory size"),
    centralOffset: checkedSafeInteger(content.readBigUInt64LE(recordOffset + 48), "ZIP64 central-directory offset"),
  };
}

function decodeArchiveString(value: Buffer, label: string): string {
  const decoded = value.toString("utf8");
  if (decoded.includes("\ufffd")) unsafe(`${label} is not valid UTF-8`);
  return decoded;
}

function decodeZipPortableString(value: Buffer, flags: number, label: string): string {
  // ZIP bit 11 is the only portable promise that a filename is UTF-8. Without
  // it, extractors interpret high bytes through legacy encodings such as CP437,
  // so validating them as UTF-8 can inspect a different name than is written.
  // ASCII is invariant across those encodings and remains safe.
  if ((flags & 0x0800) === 0 && value.some((byte) => byte >= 0x80)) {
    unsafe(`legacy-encoded ${label} must be ASCII`);
  }
  return decodeArchiveString(value, label);
}

interface ZipLocalPayload {
  compressed: Buffer;
  start: number;
  end: number;
}

function zipLocalPayload(content: Buffer, entry: ZipEntry, centralOffset: number): ZipLocalPayload {
  const offset = entry.localHeaderOffset;
  if (offset < 0 || offset + ZIP_LOCAL_HEADER_SIZE > centralOffset || content.readUInt32LE(offset) !== 0x04034b50) {
    unsafe(`local header for "${entry.path || "."}" is missing or malformed`);
  }
  const localFlags = content.readUInt16LE(offset + 6);
  const localMethod = content.readUInt16LE(offset + 8);
  const localCrc32 = content.readUInt32LE(offset + 14);
  let localCompressedSize = content.readUInt32LE(offset + 18);
  let localUncompressedSize = content.readUInt32LE(offset + 22);
  const filenameLength = content.readUInt16LE(offset + 26);
  const extraLength = content.readUInt16LE(offset + 28);
  const nameStart = offset + ZIP_LOCAL_HEADER_SIZE;
  const extraStart = nameStart + filenameLength;
  const dataStart = extraStart + extraLength;
  const dataEnd = dataStart + entry.compressedSize;
  if (localFlags !== entry.flags || localMethod !== entry.compressionMethod || dataEnd > centralOffset ||
      extraStart > centralOffset || dataStart > centralOffset ||
      !content.subarray(nameStart, extraStart).equals(entry.filenameBytes)) {
    unsafe(`local header for "${entry.path || "."}" is inconsistent`);
  }
  const localExtra = content.subarray(extraStart, dataStart);
  validateZipExtraFields(localExtra, `local header for "${entry.path || "."}"`);
  if ((entry.flags & 0x08) === 0) {
    const zip64 = parseZip64Extra(localExtra, localUncompressedSize === 0xffffffff, localCompressedSize === 0xffffffff, false);
    if (zip64.uncompressedSize !== undefined) localUncompressedSize = zip64.uncompressedSize;
    if (zip64.compressedSize !== undefined) localCompressedSize = zip64.compressedSize;
    if (localCrc32 !== entry.crc32 || localCompressedSize !== entry.compressedSize || localUncompressedSize !== entry.uncompressedSize) {
      unsafe(`local sizes for "${entry.path || "."}" disagree with the central directory`);
    }
  }

  let regionEnd = dataEnd;
  if ((entry.flags & 0x08) !== 0) {
    let descriptor = dataEnd;
    if (descriptor + 4 <= centralOffset && content.readUInt32LE(descriptor) === 0x08074b50) descriptor += 4;
    const zip64Descriptor = entry.compressedSize > 0xffffffff || entry.uncompressedSize > 0xffffffff;
    const descriptorSize = zip64Descriptor ? 20 : 12;
    if (descriptor + descriptorSize > centralOffset) unsafe(`data descriptor for "${entry.path || "."}" is truncated`);
    const descriptorCrc = content.readUInt32LE(descriptor);
    const descriptorCompressed = zip64Descriptor
      ? checkedSafeInteger(content.readBigUInt64LE(descriptor + 4), "ZIP64 descriptor compressed size")
      : content.readUInt32LE(descriptor + 4);
    const descriptorUncompressed = zip64Descriptor
      ? checkedSafeInteger(content.readBigUInt64LE(descriptor + 12), "ZIP64 descriptor uncompressed size")
      : content.readUInt32LE(descriptor + 8);
    if (descriptorCrc !== entry.crc32 || descriptorCompressed !== entry.compressedSize || descriptorUncompressed !== entry.uncompressedSize) {
      unsafe(`data descriptor for "${entry.path || "."}" is inconsistent`);
    }
    regionEnd = descriptor + descriptorSize;
  }
  return { compressed: content.subarray(dataStart, dataEnd), start: offset, end: regionEnd };
}

function decodeZipPayload(entry: ZipEntry, compressed: Buffer): Buffer {
  if (entry.compressionMethod === 0) {
    if (entry.compressedSize !== entry.uncompressedSize) unsafe(`stored ZIP member "${entry.path || "."}" has inconsistent sizes`);
    return Buffer.from(compressed);
  }
  if (entry.compressionMethod !== 8) unsafe(`member "${entry.path || "."}" uses unsupported ZIP compression method ${entry.compressionMethod}`);
  try {
    const expanded = inflateRawSync(compressed, { maxOutputLength: entry.uncompressedSize + 1 });
    if (expanded.length !== entry.uncompressedSize) unsafe(`member "${entry.path || "."}" expands beyond its declared size`);
    return expanded;
  } catch (error) {
    if (error instanceof ArchiveSecurityError) throw error;
    unsafe(`member "${entry.path || "."}" payload cannot be decompressed safely`);
  }
}
export function preflightZipArchive(archivePath: string): void {
  const content = readBoundedArchive(path.resolve(archivePath));
  const eocdOffset = findZipEndOfCentralDirectory(content);
  const location = parseZipDirectoryLocation(content, eocdOffset);
  if (location.entryCount > ARCHIVE_MAX_ENTRIES) unsafe(`entry count exceeds ${ARCHIVE_MAX_ENTRIES}`);
  const centralEnd = location.centralOffset + location.centralSize;
  if (!Number.isSafeInteger(centralEnd) || location.centralOffset < 0 || centralEnd > eocdOffset) unsafe("ZIP central-directory bounds are invalid");

  const entries: ZipEntry[] = [];
  let expandedBytes = 0;
  let cursor = location.centralOffset;
  for (let index = 0; index < location.entryCount; index++) {
    if (cursor + ZIP_CENTRAL_HEADER_SIZE > centralEnd || content.readUInt32LE(cursor) !== 0x02014b50) unsafe("ZIP central-directory entry is missing or truncated");
    const madeBy = content.readUInt16LE(cursor + 4);
    const flags = content.readUInt16LE(cursor + 8);
    const compressionMethod = content.readUInt16LE(cursor + 10);
    const crc32 = content.readUInt32LE(cursor + 16);
    let compressedSize = content.readUInt32LE(cursor + 20);
    let uncompressedSize = content.readUInt32LE(cursor + 24);
    const filenameLength = content.readUInt16LE(cursor + 28);
    const extraLength = content.readUInt16LE(cursor + 30);
    const commentLength = content.readUInt16LE(cursor + 32);
    const diskStart = content.readUInt16LE(cursor + 34);
    const externalAttributes = content.readUInt32LE(cursor + 38);
    let localHeaderOffset = content.readUInt32LE(cursor + 42);
    const entryEnd = cursor + ZIP_CENTRAL_HEADER_SIZE + filenameLength + extraLength + commentLength;
    if (entryEnd > centralEnd) unsafe("ZIP central-directory entry is truncated");
    if ((flags & 1) !== 0) unsafe("encrypted ZIP entries are not supported");
    if (diskStart !== 0 && diskStart !== 0xffff) unsafe("multi-disk ZIP entries are not supported");
    const filenameBytes = Buffer.from(content.subarray(cursor + ZIP_CENTRAL_HEADER_SIZE, cursor + ZIP_CENTRAL_HEADER_SIZE + filenameLength));
    const extra = content.subarray(cursor + ZIP_CENTRAL_HEADER_SIZE + filenameLength, cursor + ZIP_CENTRAL_HEADER_SIZE + filenameLength + extraLength);
    validateZipExtraFields(extra, `central header for entry ${index + 1}`);
    const zip64 = parseZip64Extra(extra, uncompressedSize === 0xffffffff, compressedSize === 0xffffffff, localHeaderOffset === 0xffffffff);
    if (zip64.uncompressedSize !== undefined) uncompressedSize = zip64.uncompressedSize;
    if (zip64.compressedSize !== undefined) compressedSize = zip64.compressedSize;
    if (zip64.localOffset !== undefined) localHeaderOffset = zip64.localOffset;
    expandedBytes = addExpandedBytes(expandedBytes, uncompressedSize);
    const rawName = decodeZipPortableString(filenameBytes, flags, "ZIP member name");

    const hostSystem = madeBy >>> 8;
    const unixType = (externalAttributes >>> 16) & 0o170000;
    let kind: ArchiveEntryKind;
    if (hostSystem !== 3 && unixType !== 0) {
      unsafe(`member "${rawName}" has ambiguous Unix type bits from ZIP host ${hostSystem}`);
    }
    if (hostSystem === 3 && unixType !== 0) {
      if (unixType === 0o040000) kind = "directory";
      else if (unixType === 0o100000) kind = "file";
      else if (unixType === 0o120000) kind = "symlink";
      else unsafe(`member "${rawName}" is a special filesystem node`);
    } else kind = rawName.endsWith("/") || (externalAttributes & 0x10) !== 0 ? "directory" : "file";
    const normalizedPath = normalizeMemberPath(rawName, "entry path", kind === "directory");
    if (kind === "directory" && uncompressedSize !== 0) unsafe(`directory "${normalizedPath || "."}" has a data payload`);
    entries.push({ path: normalizedPath, kind, compressedSize, uncompressedSize, compressionMethod, flags, crc32, localHeaderOffset, filenameBytes });
    cursor = entryEnd;
  }
  if (cursor !== centralEnd) unsafe("ZIP central directory contains unparsed or inconsistent data");
  const localRegions: Array<{ start: number; end: number; path: string }> = [];
  for (const entry of entries) {
    const local = zipLocalPayload(content, entry, location.centralOffset);
    const expanded = decodeZipPayload(entry, local.compressed);
    if (entry.kind === "directory" && expanded.length !== 0) unsafe(`directory "${entry.path || "."}" has a payload`);
    if (entry.kind === "symlink") {
      if (expanded.length > MAX_LINK_TARGET_BYTES) unsafe(`link "${entry.path}" target is too large`);
      entry.target = resolveRelativeTarget(
        entry.path,
        decodeZipPortableString(expanded, entry.flags, `ZIP link "${entry.path}" target`),
      );
    }
    localRegions.push({ start: local.start, end: local.end, path: entry.path || "." });
  }
  localRegions.sort((left, right) => left.start - right.start || left.end - right.end);
  for (let index = 1; index < localRegions.length; index++) {
    if (localRegions[index]!.start < localRegions[index - 1]!.end) {
      unsafe(`local ZIP regions for "${localRegions[index - 1]!.path}" and "${localRegions[index]!.path}" overlap`);
    }
  }
  validateArchiveGraph(entries.filter((entry) => entry.path.length > 0));
}

function parseTarNumber(field: Buffer, label: string): number {
  if (field.length === 0) unsafe(`${label} is missing`);
  if ((field[0]! & 0x80) !== 0) {
    const bytes = Buffer.from(field);
    const negative = (bytes[0]! & 0x40) !== 0;
    bytes[0] = bytes[0]! & 0x7f;
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (negative) unsafe(`${label} is negative`);
    return checkedSafeInteger(value, label);
  }
  const raw = field.toString("ascii").replace(/\0.*$/s, "").trim();
  if (raw.length === 0) return 0;
  if (!/^[0-7]+$/.test(raw)) unsafe(`${label} is not a valid octal number`);
  return checkedSafeInteger(BigInt(`0o${raw}`), label);
}

function decodeLegacyTarString(value: Buffer, label: string): string {
  if (value.some((byte) => byte >= 0x80)) {
    unsafe(`${label} must be ASCII; use a UTF-8 PAX path or linkpath record`);
  }
  return value.toString("ascii");
}

function tarFieldBytes(header: Buffer, start: number, length: number): Buffer {
  const field = header.subarray(start, start + length);
  const nul = field.indexOf(0);
  return nul === -1 ? field : field.subarray(0, nul);
}

function verifyTarChecksum(header: Buffer): void {
  const expected = parseTarNumber(header.subarray(148, 156), "tar checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index++) actual += index >= 148 && index < 156 ? 0x20 : header[index]!;
  if (actual !== expected) unsafe("tar header checksum is invalid");
}

function parsePax(content: Buffer): TarOverrides {
  const result: TarOverrides = {};
  let cursor = 0;
  while (cursor < content.length) {
    const space = content.indexOf(0x20, cursor);
    if (space === -1) unsafe("PAX record length is missing");
    const rawLength = content.subarray(cursor, space).toString("ascii");
    if (!/^[1-9][0-9]*$/.test(rawLength)) unsafe("PAX record length is invalid");
    const length = Number(rawLength);
    if (!Number.isSafeInteger(length) || length <= space - cursor + 1 || cursor + length > content.length || content[cursor + length - 1] !== 0x0a) unsafe("PAX record is truncated or malformed");
    const record = decodeArchiveString(content.subarray(space + 1, cursor + length - 1), "PAX record");
    const equals = record.indexOf("=");
    if (equals <= 0) unsafe("PAX record is malformed");
    const key = record.slice(0, equals);
    const value = record.slice(equals + 1);
    if (key === "path" || key === "linkpath") {
      if (Buffer.byteLength(value, "utf8") > MAX_LINK_TARGET_BYTES) {
        unsafe(`PAX ${key} exceeds ${MAX_LINK_TARGET_BYTES} bytes`);
      }
      if (key === "path") result.path = value;
      else result.linkpath = value;
    }
    else if (key === "size") {
      if (!/^(?:0|[1-9][0-9]*)$/.test(value)) unsafe("PAX size is invalid");
      result.size = checkedSafeInteger(BigInt(value), "PAX size");
    } else if (key.startsWith("GNU.sparse.") || key === "SCHILY.realsize" || key === "SCHILY.filetype") result.sparse = true;
    cursor += length;
  }
  return result;
}

function readTarPayload(content: Buffer, dataStart: number, size: number): Buffer {
  const dataEnd = dataStart + size;
  if (!Number.isSafeInteger(dataEnd) || dataEnd > content.length) unsafe("tar entry payload is truncated");
  return content.subarray(dataStart, dataEnd);
}

function decompressTarArchive(archivePath: string, content: Buffer): Buffer {
  if (content.length >= 2 && content[0] === 0x1f && content[1] === 0x8b) {
    try { return gunzipSync(content, { maxOutputLength: ARCHIVE_MAX_EXPANDED_BYTES + 1 }); }
    catch { unsafe("gzip-compressed tar data is invalid or exceeds the expansion limit"); }
  }
  const isBzip2 = content.length >= 3 && content[0] === 0x42 && content[1] === 0x5a && content[2] === 0x68;
  const isXz = content.length >= 6 && content.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]));
  if (isBzip2 || isXz) {
    try {
      return execFileSync(isBzip2 ? "bzip2" : "xz", ["-dc", archivePath], {
        encoding: "buffer", maxBuffer: ARCHIVE_MAX_EXPANDED_BYTES + 1, stdio: ["ignore", "pipe", "pipe"],
      });
    } catch { unsafe(`${isBzip2 ? "bzip2" : "xz"}-compressed tar data cannot be inspected safely`); }
  }
  return content;
}

export function preflightTarArchive(archivePath: string): void {
  const resolvedArchivePath = path.resolve(archivePath);
  const compressed = readBoundedArchive(resolvedArchivePath);
  const content = decompressTarArchive(resolvedArchivePath, compressed);
  if (content.length > ARCHIVE_MAX_EXPANDED_BYTES) unsafe(`tar expansion exceeds ${ARCHIVE_MAX_EXPANDED_BYTES} bytes`);
  if (content.length % TAR_BLOCK_SIZE !== 0) unsafe("tar data is not block-aligned");
  const entries: ArchiveEntry[] = [];
  let expandedBytes = 0;
  let headerCount = 0;
  let cursor = 0;
  let sawEndMarker = false;
  let nextOverrides: TarOverrides = {};
  let globalOverrides: TarOverrides = {};
  while (cursor + TAR_BLOCK_SIZE <= content.length) {
    const header = content.subarray(cursor, cursor + TAR_BLOCK_SIZE);
    if (header.every((byte) => byte === 0)) {
      if (cursor + TAR_BLOCK_SIZE * 2 > content.length || !content.subarray(cursor + TAR_BLOCK_SIZE, cursor + TAR_BLOCK_SIZE * 2).every((byte) => byte === 0)) unsafe("tar end marker is incomplete");
      sawEndMarker = true;
      cursor += TAR_BLOCK_SIZE * 2;
      break;
    }
    headerCount++;
    if (headerCount > ARCHIVE_MAX_ENTRIES) unsafe(`entry count exceeds ${ARCHIVE_MAX_ENTRIES}`);
    verifyTarChecksum(header);
    const headerNameBytes = tarFieldBytes(header, 0, 100);
    const posixUstar =
      header.subarray(257, 263).equals(Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72, 0x00])) &&
      header[263] === 0x30 &&
      header[264] === 0x30;
    // Bytes 345..499 are a pathname prefix only in POSIX ustar/PAX. Old-GNU
    // uses the same region for timestamps and sparse metadata; V7 leaves it
    // outside the header. Treating either as a prefix validates a path that the
    // extractor never writes.
    const prefixBytes = posixUstar
      ? tarFieldBytes(header, 345, 155)
      : Buffer.alloc(0);
    const rawHeaderLinkBytes = tarFieldBytes(header, 157, 100);
    const typeFlag = header[156] === 0 ? "0" : String.fromCharCode(header[156]!);
    const headerSize = parseTarNumber(header.subarray(124, 136), "tar entry size");
    const overrides = { ...globalOverrides, ...nextOverrides };
    const metadataRecord = typeFlag === "x" || typeFlag === "g" ||
      typeFlag === "L" || typeFlag === "K";
    const size = metadataRecord ? headerSize : (overrides.size ?? headerSize);
    if ((!metadataRecord && overrides.sparse) || typeFlag === "S") {
      unsafe("sparse tar entries are not supported");
    }
    const dataStart = cursor + TAR_BLOCK_SIZE;
    expandedBytes = addExpandedBytes(expandedBytes, size);
    const payload = readTarPayload(content, dataStart, size);
    const nextCursor = dataStart + Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
    if (!Number.isSafeInteger(nextCursor) || nextCursor > content.length) unsafe("tar entry padding is truncated");
    if (typeFlag === "x" || typeFlag === "g") {
      const parsed = parsePax(payload);
      if (typeFlag === "g") globalOverrides = { ...globalOverrides, ...parsed };
      else nextOverrides = { ...nextOverrides, ...parsed };
      cursor = nextCursor;
      continue;
    }
    if (typeFlag === "L" || typeFlag === "K") {
      if (size > MAX_LINK_TARGET_BYTES) unsafe("GNU tar long-name record is too large");
      const nul = payload.indexOf(0);
      const value = decodeLegacyTarString(
        nul === -1 ? payload : payload.subarray(0, nul),
        "GNU tar long-name record",
      );
      nextOverrides = typeFlag === "L"
        ? { ...nextOverrides, path: value }
        : { ...nextOverrides, linkpath: value };
      cursor = nextCursor;
      continue;
    }
    const selectedOverrides = { ...globalOverrides, ...nextOverrides };
    let rawPath = selectedOverrides.path;
    if (rawPath === undefined) {
      const headerName = decodeLegacyTarString(headerNameBytes, "tar header name");
      const prefix = decodeLegacyTarString(prefixBytes, "tar header prefix");
      rawPath = prefix ? `${prefix}/${headerName}` : headerName;
    }
    let rawLink = selectedOverrides.linkpath;
    if (rawLink === undefined && (typeFlag === "1" || typeFlag === "2")) {
      rawLink = decodeLegacyTarString(rawHeaderLinkBytes, "tar header link target");
    }
    rawLink ??= "";
    nextOverrides = {};
    const normalizedPath = normalizeMemberPath(rawPath, "entry path", typeFlag === "5");
    let entry: ArchiveEntry;
    if (typeFlag === "0" || typeFlag === "7") entry = { path: normalizedPath, kind: "file" };
    else if (typeFlag === "5") {
      if (size !== 0) unsafe(`directory "${normalizedPath}" has a data payload`);
      entry = { path: normalizedPath, kind: "directory" };
    } else if (typeFlag === "2") {
      if (size !== 0) unsafe(`symlink "${normalizedPath}" has a data payload`);
      entry = { path: normalizedPath, kind: "symlink", target: resolveRelativeTarget(normalizedPath, rawLink) };
    } else if (typeFlag === "1") {
      if (size !== 0) unsafe(`hardlink "${normalizedPath}" has a data payload`);
      entry = { path: normalizedPath, kind: "hardlink", target: resolveHardlinkTarget(normalizedPath, rawLink) };
    } else if (["3", "4", "6"].includes(typeFlag)) unsafe(`member "${normalizedPath}" is a special filesystem node`);
    else unsafe(`member "${normalizedPath}" uses unsupported tar type "${typeFlag}"`);
    entries.push(entry);
    cursor = nextCursor;
  }
  if (!sawEndMarker) unsafe("tar end marker is missing");
  if (!content.subarray(cursor).every((byte) => byte === 0)) unsafe("tar contains non-zero data after its end marker");
  if (Object.keys(nextOverrides).length > 0) unsafe("tar ends with metadata that does not describe a member");
  validateArchiveGraph(entries.filter((entry) => entry.path.length > 0));
}

export function extractZip(archivePath: string, extractDir: string, overwrite = false): void {
  const resolvedArchivePath = path.resolve(archivePath);
  const resolvedExtractDir = path.resolve(extractDir);
  preflightZipArchive(resolvedArchivePath);
  fs.mkdirSync(resolvedExtractDir, { recursive: true });

  if (process.platform === "win32") {
    // Modern Windows ships bsdtar in System32. It auto-detects ZIP and avoids
    // making runtime extraction depend on a separately installed Info-ZIP.
    const windowsRoot = process.env.SystemRoot || "C:\\Windows";
    const tarPath = path.win32.join(windowsRoot, "System32", "tar.exe");
    if (!fs.existsSync(tarPath)) {
      throw new Error(
        `ZIP extraction backend is unavailable: expected Windows bsdtar at ${tarPath}`,
      );
    }
    const args = ["-x"];
    if (!overwrite) args.push("-k");
    args.push("-f", resolvedArchivePath, "-C", resolvedExtractDir);
    execFileSync(tarPath, args, { stdio: "pipe" });
    return;
  }

  const args = ["-q"];
  if (overwrite) args.push("-o");
  args.push(resolvedArchivePath, "-d", resolvedExtractDir);
  execFileSync("unzip", args, { stdio: "pipe" });
}

export function extractTar(archivePath: string, extractDir: string): void {
  const resolvedArchivePath = path.resolve(archivePath);
  const resolvedExtractDir = path.resolve(extractDir);
  preflightTarArchive(resolvedArchivePath);
  execFileSync("tar", ["xf", resolvedArchivePath, "-C", resolvedExtractDir], { stdio: "pipe" });
}

export function extractTarGz(archivePath: string, extractDir: string): void {
  const resolvedArchivePath = path.resolve(archivePath);
  const resolvedExtractDir = path.resolve(extractDir);
  preflightTarArchive(resolvedArchivePath);
  execFileSync("tar", ["xzf", resolvedArchivePath, "-C", resolvedExtractDir], { stdio: "pipe" });
}
