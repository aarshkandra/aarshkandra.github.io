using System.Text;
using System.Text.Json.Nodes;
using AarshRemote.Agent.Protocol;
using Xunit;

namespace AarshRemote.Agent.Tests;

public class ProtocolVectorTests
{
    private static string Dev => Vectors.Str("deviceUuid");
    private static byte[] ServerPub => Vectors.B64("serverPublicKeyRaw");

    [Fact]
    public void Canonical_matches_typescript_for_simple_input() =>
        Assert.Equal(Vectors.Obj("canonical")["output"]!.GetValue<string>(), Canonical.Serialize(Vectors.Obj("canonical")["input"]));

    [Fact]
    public void Canonical_matches_typescript_for_escapes_unicode_and_lone_surrogates()
    {
        // System.Text.Json refuses to *read* a lone surrogate, so the shared vector's "lone" member is checked via a built value.
        var c = Vectors.Obj("canonicalUnicode");
        var input = (JsonObject)c["input"]!.DeepClone();
        input.Remove("lone");
        var expected = c["output"]!.GetValue<string>().Replace("\"lone\":\"x\\ud800y\",", "");
        Assert.Equal(expected, Canonical.Serialize(input));
        Assert.Equal("{\"v\":\"x\\ud800y\"}", Canonical.Serialize(new JsonObject { ["v"] = "x\ud800y" }));
    }

    [Fact]
    public void Unreadable_unicode_in_an_envelope_is_Malformed_not_a_crash()
    {
        var e = Vectors.Envelope();
        var text = e.ToJsonString().Replace("RESTART", "REST\\ud800");
        var node = JsonNode.Parse(text);
        Assert.Equal(EnvelopeError.Malformed, EnvelopeVerifier.Verify(node, ServerPub, Dev, Vectors.Now).Error);
    }

    [Fact]
    public void Canonical_rejects_non_integer_numbers() =>
        Assert.Throws<FormatException>(() => Canonical.Serialize(JsonNode.Parse("{\"a\":1.5}")));

    [Fact]
    public void Keys_derived_from_seeds_match_the_vectors()
    {
        Assert.Equal(Vectors.Str("serverPublicKeyRaw"), Convert.ToBase64String(Ed25519.PublicKeyFromSeed(Vectors.B64("serverSeed"))));
        Assert.Equal(Vectors.Str("agentPublicKeyRaw"), Convert.ToBase64String(Ed25519.PublicKeyFromSeed(Vectors.B64("agentSeed"))));
    }

    [Fact]
    public void Hello_signature_is_byte_identical_to_typescript()
    {
        var c = Vectors.Obj("helloChallenge");
        var sig = Signing.SignHello(Vectors.B64("agentSeed"), c["nonce"]!.GetValue<string>(), c["deviceUuid"]!.GetValue<string>(), c["serverOrigin"]!.GetValue<string>(), c["ts"]!.GetValue<long>());
        Assert.Equal(Vectors.Str("helloSig"), sig); // Ed25519 is deterministic
    }

    [Fact]
    public void Pairing_poll_signature_is_byte_identical_to_typescript()
    {
        var p = Vectors.Obj("pairingPoll");
        var sig = Convert.ToBase64String(Ed25519.Sign(Vectors.B64("agentSeed"), Signing.PairingPollInput(p["requestId"]!.GetValue<string>(), p["ts"]!.GetValue<long>())));
        Assert.Equal(p["sig"]!.GetValue<string>(), sig);
    }

    [Fact]
    public void Signing_input_is_identical_to_typescript()
    {
        var env = Vectors.Envelope();
        env.Remove("type"); env.Remove("sig");
        Assert.Equal(Vectors.Str("envelopeSigningInput"), Signing.EnvelopeDomain + Canonical.Serialize(env));
    }

    [Fact]
    public void Accepts_typescript_signed_envelope()
    {
        var (cmd, err) = EnvelopeVerifier.Verify(Vectors.Envelope(), ServerPub, Dev, Vectors.Now);
        Assert.Null(err);
        Assert.Equal("RESTART", cmd!.Cmd);
        Assert.Equal(5, cmd.Args["delaySeconds"]!.GetValue<int>());
    }

    [Fact]
    public void Rejects_tampered_cmd_and_args()
    {
        var e = Vectors.Envelope(); e["cmd"] = "SHUTDOWN";
        Assert.Equal(EnvelopeError.BadSignature, EnvelopeVerifier.Verify(e, ServerPub, Dev, Vectors.Now).Error);
        var f = Vectors.Envelope(); f["args"]!["delaySeconds"] = 0;
        Assert.Equal(EnvelopeError.BadSignature, EnvelopeVerifier.Verify(f, ServerPub, Dev, Vectors.Now).Error);
    }

    [Fact]
    public void Rejects_wrong_server_key_wrong_device_expired_and_future()
    {
        var other = Ed25519.PublicKeyFromSeed(Vectors.B64("agentSeed"));
        Assert.Equal(EnvelopeError.BadSignature, EnvelopeVerifier.Verify(Vectors.Envelope(), other, Dev, Vectors.Now).Error);
        Assert.Equal(EnvelopeError.WrongDevice, EnvelopeVerifier.Verify(Vectors.Envelope(), ServerPub, Guid.NewGuid().ToString(), Vectors.Now).Error);
        Assert.Equal(EnvelopeError.Expired, EnvelopeVerifier.Verify(Vectors.Envelope(), ServerPub, Dev, 1790000031).Error);
        Assert.Equal(EnvelopeError.NotYetValid, EnvelopeVerifier.Verify(Vectors.Envelope(), ServerPub, Dev, 1789999900).Error);
    }

    [Fact]
    public void Rejects_malformed_and_unknown_commands()
    {
        Assert.Equal(EnvelopeError.Malformed, EnvelopeVerifier.Verify(null, ServerPub, Dev, Vectors.Now).Error);
        Assert.Equal(EnvelopeError.Malformed, EnvelopeVerifier.Verify(JsonNode.Parse("{\"foo\":1}"), ServerPub, Dev, Vectors.Now).Error);
        var e = Vectors.Envelope(); e["cmd"] = "EXECUTE_COMMAND";
        Assert.Equal(EnvelopeError.Malformed, EnvelopeVerifier.Verify(e, ServerPub, Dev, Vectors.Now).Error);
        var g = Vectors.Envelope(); g["sig"] = "not base64!!";
        Assert.Equal(EnvelopeError.Malformed, EnvelopeVerifier.Verify(g, ServerPub, Dev, Vectors.Now).Error);
    }

    [Fact]
    public void Rejects_properly_signed_but_over_long_lifetime_and_bad_args()
    {
        var seed = Vectors.B64("serverSeed");
        JsonObject Signed(string cmd, JsonObject args, long issued, long expires)
        {
            var body = new JsonObject { ["id"] = Guid.NewGuid().ToString(), ["cmd"] = cmd, ["args"] = args, ["issuedAt"] = issued, ["expiresAt"] = expires, ["nonce"] = "AAAAAAAAAAAAAAAAAAAAAA==", ["deviceUuid"] = Dev };
            var sig = Convert.ToBase64String(Ed25519.Sign(seed, Encoding.UTF8.GetBytes(Signing.EnvelopeDomain + Canonical.Serialize(body))));
            body["type"] = "command"; body["sig"] = sig;
            return body;
        }
        Assert.Equal(EnvelopeError.LifetimeTooLong, EnvelopeVerifier.Verify(Signed("SLEEP", new JsonObject(), Vectors.Now, Vectors.Now + 3600), ServerPub, Dev, Vectors.Now).Error);
        Assert.Equal(EnvelopeError.BadArgs, EnvelopeVerifier.Verify(Signed("SLEEP", new JsonObject { ["x"] = 1 }, Vectors.Now, Vectors.Now + 30), ServerPub, Dev, Vectors.Now).Error);
        Assert.Equal(EnvelopeError.BadArgs, EnvelopeVerifier.Verify(Signed("RESTART", new JsonObject { ["delaySeconds"] = 999 }, Vectors.Now, Vectors.Now + 30), ServerPub, Dev, Vectors.Now).Error);
        Assert.Null(EnvelopeVerifier.Verify(Signed("PREPARE_CONNECT", new JsonObject { ["ttlSeconds"] = 120 }, Vectors.Now, Vectors.Now + 30), ServerPub, Dev, Vectors.Now).Error);
    }

    [Theory]
    [InlineData("PREPARE_CONNECT", "{\"ttlSeconds\":5}", false)]
    [InlineData("PREPARE_CONNECT", "{\"ttlSeconds\":120,\"x\":1}", false)]
    [InlineData("DISCONNECT", "{\"sessionId\":\"nope\"}", false)]
    [InlineData("DISCONNECT", "{\"sessionId\":\"22222222-2222-4222-8222-222222222222\"}", true)]
    [InlineData("RESTART", "{}", true)]
    [InlineData("RESTART", "{\"delaySeconds\":1.5}", false)]
    [InlineData("SLEEP", "{\"cmd\":\"calc.exe\"}", false)]
    public void Argument_validation_is_strict(string cmd, string json, bool ok) =>
        Assert.Equal(ok, CommandSpec.ValidArgs(cmd, (JsonObject)JsonNode.Parse(json)!));

    [Fact]
    public void Allow_list_has_no_generic_execute()
    {
        Assert.DoesNotContain(CommandSpec.All, c => c.Contains("EXEC") || c.Contains("SHELL") || c.Contains("RUN"));
        Assert.False(CommandSpec.ValidArgs("EXECUTE_COMMAND", new JsonObject()));
    }
}
