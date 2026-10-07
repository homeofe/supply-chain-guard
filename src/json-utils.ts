/** True only for JSON object values, never null, arrays, or primitives. */
export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Drop a leading U+FEFF. JSON.parse rejects it, but npm strips it before
 * parsing a manifest, so a package.json that starts with a BOM still runs its
 * install hooks on `npm install`.
 */
export function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

/** Parse a JSON object without allowing valid-but-wrong-shaped JSON through. */
export function parseJsonObject(content: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(stripBom(content));
    return isJsonObject(value) ? value : undefined;
  } catch {
    return undefined;
  }
}
