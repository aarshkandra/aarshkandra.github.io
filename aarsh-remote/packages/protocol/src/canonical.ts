/**
 * Canonical JSON: object keys sorted (by UTF-16 code unit), no whitespace, `undefined` members dropped.
 * Only JSON-safe values are accepted (finite numbers, strings, booleans, null, arrays, plain objects).
 * Every implementation (TS, C#, Go) must produce byte-identical output; see test-vectors.json.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new Error("non-finite number in canonical JSON");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
    }
    default:
      throw new Error(`unsupported type in canonical JSON: ${typeof value}`);
  }
}
