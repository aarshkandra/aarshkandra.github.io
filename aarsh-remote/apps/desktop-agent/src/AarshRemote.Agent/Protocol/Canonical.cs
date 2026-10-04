using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AarshRemote.Agent.Protocol;

/// <summary>
/// Canonical JSON, byte-identical to packages/protocol/src/canonical.ts: object keys sorted by UTF-16 code unit,
/// no whitespace, integers only, strings escaped exactly like JavaScript's JSON.stringify.
/// </summary>
internal static class Canonical
{
    public static string Serialize(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(sb, node);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, JsonNode? node)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                break;
            case JsonObject obj:
                sb.Append('{');
                var first = true;
                foreach (var key in obj.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, key);
                    sb.Append(':');
                    Write(sb, obj[key]);
                }
                sb.Append('}');
                break;
            case JsonArray arr:
                sb.Append('[');
                for (var i = 0; i < arr.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    Write(sb, arr[i]);
                }
                sb.Append(']');
                break;
            case JsonValue val:
                WriteValue(sb, val);
                break;
        }
    }

    private static void WriteValue(StringBuilder sb, JsonValue val)
    {
        // Works for both parsed (JsonElement-backed) and programmatically built values.
        switch (val.GetValueKind())
        {
            case JsonValueKind.String: WriteString(sb, val.GetValue<string>()); break;
            case JsonValueKind.True: sb.Append("true"); break;
            case JsonValueKind.False: sb.Append("false"); break;
            case JsonValueKind.Null: sb.Append("null"); break;
            case JsonValueKind.Number:
                if (!JsonInt.TryGet(val, out var n)) throw new FormatException("only integer numbers are allowed in signed messages");
                sb.Append(n.ToString(CultureInfo.InvariantCulture));
                break;
            default: throw new FormatException("unsupported JSON value");
        }
    }

    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[++i]); }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture)); // lone surrogate: JSON.stringify escapes it
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }
}

internal static class JsonInt
{
    /// <summary>Reads an integer from a parsed or programmatically built JSON number, rejecting fractions and exponents.</summary>
    public static bool TryGet(JsonNode? node, out long value)
    {
        value = 0;
        if (node is not JsonValue v || v.GetValueKind() != JsonValueKind.Number) return false;
        var text = v.ToJsonString();
        if (text.Length == 0 || text.Length > 18) return false;
        foreach (var (c, i) in text.Select((c, i) => (c, i)))
            if (!(char.IsAsciiDigit(c) || (i == 0 && c == '-' && text.Length > 1))) return false;
        return long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }
}
