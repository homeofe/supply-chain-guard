/** True only for JSON object values, never null, arrays, or primitives. */
export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Parse a JSON object without allowing valid-but-wrong-shaped JSON through. */
export function parseJsonObject(content: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(content);
    return isJsonObject(value) ? value : undefined;
  } catch {
    return undefined;
  }
}
