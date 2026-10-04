using System.Text.Json;
using System.Text.Json.Nodes;

namespace AarshRemote.Agent.Tests;

/// <summary>Loads packages/protocol/test/vectors.json (TypeScript is the reference implementation).</summary>
internal static class Vectors
{
    public static readonly JsonObject Doc = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")))!;
    public static string Str(string key) => Doc[key]!.GetValue<string>();
    public static byte[] B64(string key) => Convert.FromBase64String(Str(key));
    public static JsonObject Obj(string key) => (JsonObject)Doc[key]!;
    public const long Now = 1790000010; // 10 s after the vector's issuedAt
    public static JsonObject Envelope() => (JsonObject)Obj("envelope").DeepClone();
}
