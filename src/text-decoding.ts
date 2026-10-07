/**
 * Decode file bytes the way the interpreter that runs them would.
 *
 * The scan reads every file as UTF-8. PowerShell, the Windows script hosts and
 * Python read UTF-16 natively, so a UTF-16 copy of a payload that is detected
 * in UTF-8 decoded to NUL-interleaved text that no rule matched, with nothing
 * in the report saying so.
 */

/** Bytes inspected for the NUL-ratio heuristic. */
const SNIFF_BYTES = 1024;

/** Fraction of NUL bytes in the sniffed window above which a file is UTF-16 without a BOM. */
const NUL_RATIO_THRESHOLD = 0.3;

export type DetectedEncoding = "utf-8" | "utf-16le" | "utf-16be";

/**
 * UTF-16 is recognised by its BOM (`FF FE`, `FE FF`) or, for a BOM-less file,
 * by NUL bytes in the first kilobyte sitting on one side of the code units:
 * ASCII text in UTF-16 has a NUL in every second byte. A lone NUL inside an
 * otherwise UTF-8 file stays UTF-8, so padding a payload with a few NULs does
 * not change how it is read.
 */
export function detectTextEncoding(bytes: Uint8Array): DetectedEncoding {
  if (bytes.length >= 2) {
    if (bytes[0] === 0xff && bytes[1] === 0xfe) return "utf-16le";
    if (bytes[0] === 0xfe && bytes[1] === 0xff) return "utf-16be";
  }
  const window = Math.min(bytes.length, SNIFF_BYTES) & ~1;
  if (window < 4) return "utf-8";
  let evenNuls = 0;
  let oddNuls = 0;
  for (let i = 0; i < window; i += 2) {
    if (bytes[i] === 0) evenNuls++;
    if (bytes[i + 1] === 0) oddNuls++;
  }
  const units = window / 2;
  // ASCII-range UTF-16LE: NUL in the high (odd) byte of each unit; BE: even.
  if (oddNuls / units >= NUL_RATIO_THRESHOLD && evenNuls / units < 0.1) return "utf-16le";
  if (evenNuls / units >= NUL_RATIO_THRESHOLD && oddNuls / units < 0.1) return "utf-16be";
  return "utf-8";
}

/** Decode UTF-16BE by swapping to LE, which Node decodes natively. */
function decodeUtf16be(bytes: Uint8Array): string {
  const swapped = Buffer.alloc(bytes.length & ~1);
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    swapped[i] = bytes[i + 1]!;
    swapped[i + 1] = bytes[i]!;
  }
  return swapped.toString("utf16le");
}

/** Decode a file's bytes as UTF-8, or as UTF-16 when the bytes say so. A leading BOM is dropped. */
export function decodeTextBytes(bytes: Buffer): string {
  const encoding = detectTextEncoding(bytes);
  let text: string;
  if (encoding === "utf-16le") text = bytes.toString("utf16le");
  else if (encoding === "utf-16be") text = decodeUtf16be(bytes);
  else text = bytes.toString("utf-8");
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}
