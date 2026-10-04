using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AarshRemote.Agent.Protocol;

internal static class CommandSpec
{
    /// <summary>The closed allow-list. There is no generic execute command.</summary>
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        "WAKE", "SLEEP", "RESTART", "SHUTDOWN", "CONNECT", "DISCONNECT", "PREPARE_CONNECT",
        "GET_STATUS", "GET_METRICS", "PAUSE_REMOTE", "RESUME_REMOTE",
    };

    /// <summary>Strict argument validation mirroring COMMAND_ARGS in packages/protocol (unknown members are rejected).</summary>
    public static bool ValidArgs(string cmd, JsonObject args)
    {
        static bool OnlyKeys(JsonObject a, params string[] keys) => a.All(p => keys.Contains(p.Key));
        static bool IntIn(JsonNode? n, long min, long max) =>
            JsonInt.TryGet(n, out var l) && l >= min && l <= max;

        switch (cmd)
        {
            case "SLEEP": case "CONNECT": case "GET_STATUS": case "GET_METRICS": case "PAUSE_REMOTE": case "RESUME_REMOTE":
                return args.Count == 0;
            case "RESTART": case "SHUTDOWN":
                return OnlyKeys(args, "delaySeconds") && (!args.ContainsKey("delaySeconds") || IntIn(args["delaySeconds"], 0, 60));
            case "PREPARE_CONNECT":
                return OnlyKeys(args, "ttlSeconds") && IntIn(args["ttlSeconds"], 30, 600);
            case "DISCONNECT":
                return OnlyKeys(args, "sessionId") && args["sessionId"] is JsonValue s && s.TryGetValue<string>(out var sid) && Guid.TryParse(sid, out _);
            case "WAKE":
                return OnlyKeys(args, "mac", "broadcast") && args["mac"] is not null && args["broadcast"] is not null;
            default:
                return false;
        }
    }
}

internal sealed record VerifiedCommand(string Id, string Cmd, JsonObject Args, long IssuedAt, long ExpiresAt);

internal enum EnvelopeError { Malformed, BadSignature, WrongDevice, Expired, NotYetValid, LifetimeTooLong, BadArgs }

internal static class EnvelopeVerifier
{
    public const int MaxLifetimeSeconds = 60;
    public const int ClockSkewSeconds = 30;

    /// <summary>Same checks and same order as verifyEnvelope() in packages/protocol/src/envelope.ts.</summary>
    public static (VerifiedCommand? Command, EnvelopeError? Error) Verify(JsonNode? raw, byte[] serverPublicKey, string expectedDeviceUuid, long nowUnix)
    {
        try { return VerifyCore(raw, serverPublicKey, expectedDeviceUuid, nowUnix); }
        catch (Exception e) when (e is InvalidOperationException or FormatException or JsonException or ArgumentException)
        {
            return (null, EnvelopeError.Malformed);
        }
    }

    private static (VerifiedCommand? Command, EnvelopeError? Error) VerifyCore(JsonNode? raw, byte[] serverPublicKey, string expectedDeviceUuid, long nowUnix)
    {
        if (raw is not JsonObject o) return (null, EnvelopeError.Malformed);
        if (!TryStr(o, "id", out var id) || !Guid.TryParse(id, out _)) return (null, EnvelopeError.Malformed);
        if (!TryStr(o, "cmd", out var cmd) || !CommandSpec.All.Contains(cmd)) return (null, EnvelopeError.Malformed);
        if (o["args"] is not JsonObject args) return (null, EnvelopeError.Malformed);
        if (!TryLong(o, "issuedAt", out var issuedAt) || !TryLong(o, "expiresAt", out var expiresAt)) return (null, EnvelopeError.Malformed);
        if (!TryStr(o, "nonce", out var nonce) || nonce.Length is < 16 or > 64) return (null, EnvelopeError.Malformed);
        if (!TryStr(o, "deviceUuid", out var deviceUuid) || !Guid.TryParse(deviceUuid, out _)) return (null, EnvelopeError.Malformed);
        if (!TryStr(o, "sig", out var sigB64)) return (null, EnvelopeError.Malformed);

        byte[] sig;
        try { sig = Convert.FromBase64String(sigB64); } catch (FormatException) { return (null, EnvelopeError.Malformed); }

        // Rebuild exactly the signed members; anything else in the message is not covered by the signature and is ignored.
        var body = new JsonObject
        {
            ["id"] = id, ["cmd"] = cmd, ["args"] = args.DeepClone(), ["issuedAt"] = issuedAt,
            ["expiresAt"] = expiresAt, ["nonce"] = nonce, ["deviceUuid"] = deviceUuid,
        };
        string canonical;
        try { canonical = Canonical.Serialize(body); } catch (FormatException) { return (null, EnvelopeError.Malformed); }
        var input = Encoding.UTF8.GetBytes(Signing.EnvelopeDomain + canonical);

        if (!Ed25519.Verify(serverPublicKey, input, sig)) return (null, EnvelopeError.BadSignature);
        if (!string.Equals(deviceUuid, expectedDeviceUuid, StringComparison.OrdinalIgnoreCase)) return (null, EnvelopeError.WrongDevice);
        if (expiresAt - issuedAt > MaxLifetimeSeconds) return (null, EnvelopeError.LifetimeTooLong);
        if (nowUnix > expiresAt) return (null, EnvelopeError.Expired);
        if (nowUnix < issuedAt - ClockSkewSeconds) return (null, EnvelopeError.NotYetValid);
        if (!CommandSpec.ValidArgs(cmd, args)) return (null, EnvelopeError.BadArgs);
        return (new VerifiedCommand(id, cmd, (JsonObject)args.DeepClone(), issuedAt, expiresAt), null);
    }

    private static bool TryStr(JsonObject o, string k, out string v)
    {
        v = "";
        if (o[k] is JsonValue jv && jv.GetValueKind() == JsonValueKind.String) { v = jv.GetValue<string>(); return true; }
        return false;
    }

    private static bool TryLong(JsonObject o, string k, out long v)
    {
        v = 0;
        return JsonInt.TryGet(o[k], out v);
    }
}
