using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Connection;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Ipc;
using AarshRemote.Agent.Pairing;
using AarshRemote.Agent.Protocol;
using Xunit;

namespace AarshRemote.Agent.Tests;

public class ServerUrlTests
{
    [Theory]
    [InlineData("https://remote.example.com", true)]
    [InlineData("https://remote.example.com:8443/", true)]
    [InlineData("http://remote.example.com", false)]       // no cleartext to the Internet, ever
    [InlineData("http://127.0.0.1:8080", false)]            // loopback http only with the dev opt-in
    [InlineData("https://user:pw@remote.example.com", false)]
    [InlineData("https://remote.example.com/?x=1", false)]
    [InlineData("not a url", false)]
    [InlineData("ftp://remote.example.com", false)]
    public void Validates_server_urls(string url, bool ok)
    {
        Environment.SetEnvironmentVariable("AARSH_ALLOW_INSECURE_HTTP", null);
        if (ok) Assert.NotNull(ServerUrl.Validate(url));
        else Assert.Throws<PairingException>(() => ServerUrl.Validate(url));
    }

    [Fact]
    public void Origin_and_websocket_url_are_derived_correctly()
    {
        var u = ServerUrl.Validate("https://remote.example.com:8443/ignored/path");
        Assert.Equal("https://remote.example.com:8443", ServerUrl.Origin(u));
        Assert.Equal("wss://remote.example.com:8443/ws/agent", ServerUrl.WebSocket(u).ToString());
        Assert.Equal("wss://remote.example.com/ws/agent", ServerUrl.WebSocket(ServerUrl.Validate("https://remote.example.com")).ToString());
    }
}

public class PairingTests : IDisposable
{
    private readonly TestEnv _e = new();
    public void Dispose() => _e.Dispose();

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> fn) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) { Requests.Add(r); return Task.FromResult(fn(r)); }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) => new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static string ServerKey => Convert.ToBase64String(Ed25519.PublicKeyFromSeed(TestEnv.ServerSeed));

    private async Task<(int Code, string Output, Handler H)> Run(Func<HttpRequestMessage, HttpResponseMessage> fn, string server = "https://remote.example.com", bool force = false)
    {
        var h = new Handler(fn);
        var output = new StringWriter();
        var code = await PairCommand.RunAsync(server, "NGP-WORKSTATION", force, _e.Paths, new IdentityStore(_e.Paths, new NoopProtector()), new ConfigStore(_e.Paths),
            new PairingClient(new HttpClient(h), TimeProvider.System), output, TimeSpan.FromMilliseconds(1), CancellationToken.None);
        return (code, output.ToString(), h);
    }

    private sealed class NoopProtector : ISecretProtector { public byte[] Protect(byte[] p) => p; public byte[] Unprotect(byte[] p) => p; public void SecureFile(string x) { } }

    private HttpResponseMessage Server(HttpRequestMessage r, string finalStatus = "paired", string origin = "https://remote.example.com", int pendingPolls = 1)
    {
        var path = r.RequestUri!.AbsolutePath;
        if (path == "/api/v1/server-info") return Json(HttpStatusCode.OK, $"{{\"origin\":\"{origin}\",\"commandPublicKey\":\"{ServerKey}\",\"minAgentVersion\":\"0.1.0\"}}");
        if (path == "/api/v1/pairing/requests" && r.Method == HttpMethod.Post)
            return Json(HttpStatusCode.Created, "{\"requestId\":\"33333333-3333-4333-8333-333333333333\",\"code\":\"847291\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        if (path.StartsWith("/api/v1/pairing/requests/"))
            return Json(HttpStatusCode.OK, $"{{\"status\":\"{(_polls++ < pendingPolls ? "pending" : finalStatus)}\"}}");
        return Json(HttpStatusCode.NotFound, "{}");
    }
    private int _polls;

    [Fact]
    public async Task Happy_path_shows_the_pairing_screen_pins_the_key_and_saves_config()
    {
        var (code, output, h) = await Run(r => Server(r));
        Assert.Equal(0, code);
        Assert.Contains("Device Pairing", output); Assert.Contains("Device: NGP-WORKSTATION", output);
        Assert.Contains("847291", output); Assert.Contains("33333333-3333-4333-8333-333333333333", output);
        var cfg = new ConfigStore(_e.Paths).Load();
        Assert.True(cfg.IsUsable);
        Assert.Equal(ServerKey, cfg.ServerCommandPublicKey);
        Assert.Equal("https://remote.example.com", cfg.ServerUrl);
        // what we sent: only the PUBLIC key
        var post = h.Requests.First(r => r.Method == HttpMethod.Post);
        var body = JsonNode.Parse(await post.Content!.ReadAsStringAsync())!;
        var id = new IdentityStore(_e.Paths, new NoopProtector()).Load()!;
        Assert.Equal(Convert.ToBase64String(id.PublicKey), body["publicKey"]!.GetValue<string>());
        Assert.Equal("DESKTOP", body["kind"]!.GetValue<string>());
        Assert.DoesNotContain("seed", body.ToJsonString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Poll_requests_are_signed_with_the_device_key()
    {
        var (_, _, h) = await Run(r => Server(r, pendingPolls: 2));
        var poll = h.Requests.First(r => r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath.Contains("/pairing/requests/"));
        var ts = long.Parse(poll.Headers.GetValues("X-Timestamp").Single());
        var sig = Convert.FromBase64String(poll.Headers.GetValues("X-Signature").Single());
        var id = new IdentityStore(_e.Paths, new NoopProtector()).Load()!;
        Assert.True(Ed25519.Verify(id.PublicKey, Signing.PairingPollInput("33333333-3333-4333-8333-333333333333", ts), sig));
    }

    [Theory]
    [InlineData("expired", 2)]
    [InlineData("burned", 2)]
    public async Task Expired_or_burned_codes_fail_without_saving_anything(string status, int expectedCode)
    {
        var (code, output, _) = await Run(r => Server(r, finalStatus: status));
        Assert.Equal(expectedCode, code);
        Assert.False(new ConfigStore(_e.Paths).Load().Paired);
        Assert.Contains(status == "burned" ? "wrong attempts" : "expired", output);
    }

    [Fact]
    public async Task Refuses_a_server_whose_origin_does_not_match_the_url()
    {
        var (code, output, _) = await Run(r => Server(r, origin: "https://other.example.com"));
        Assert.Equal(1, code);
        Assert.Contains("identifies as", output);
        Assert.False(new ConfigStore(_e.Paths).Load().Paired);
    }

    [Fact]
    public async Task Surfaces_server_errors_and_unreachable_servers_cleanly()
    {
        var (code, output, _) = await Run(r => r.RequestUri!.AbsolutePath.EndsWith("server-info") ? Server(r) : Json(HttpStatusCode.Conflict, "{\"error\":{\"code\":\"CONFLICT\"}}"));
        Assert.Equal(1, code); Assert.Contains("409 CONFLICT", output);
        var h = new Handler(_ => throw new HttpRequestException("no route to host"));
        var o = new StringWriter();
        Assert.Equal(1, await PairCommand.RunAsync("https://remote.example.com", "x", true, _e.Paths, new IdentityStore(_e.Paths, new NoopProtector()), new ConfigStore(_e.Paths), new PairingClient(new HttpClient(h), TimeProvider.System), o, TimeSpan.Zero, CancellationToken.None));
        Assert.Contains("Cannot reach the server", o.ToString());
    }

    [Fact]
    public async Task Rejects_plain_http_before_any_network_call()
    {
        Environment.SetEnvironmentVariable("AARSH_ALLOW_INSECURE_HTTP", null);
        var (code, _, h) = await Run(r => Server(r), server: "http://remote.example.com");
        Assert.Equal(1, code);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task Already_paired_is_a_no_op_and_force_creates_a_new_identity()
    {
        await Run(r => Server(r));
        var firstId = new IdentityStore(_e.Paths, new NoopProtector()).Load()!.DeviceUuid;
        _polls = 0;
        var (code, output, h) = await Run(r => Server(r));
        Assert.Equal(0, code); Assert.Contains("already paired", output); Assert.Empty(h.Requests);
        _polls = 0;
        await Run(r => Server(r), force: true);
        Assert.NotEqual(firstId, new IdentityStore(_e.Paths, new NoopProtector()).Load()!.DeviceUuid);
    }
}

public class TrayProtocolTests : IDisposable
{
    private readonly TestEnv _e = new();
    private readonly AgentStatus _status = new();
    private readonly TrayProtocol _tray;
    public TrayProtocolTests() => _tray = new TrayProtocol(_status, _e.Policy, _e.State, () => new AgentConfig { ServerUrl = "https://r.example", DeviceName = "NGP" }, _e.Paths);
    public void Dispose() => _e.Dispose();

    private JsonNode Ask(string json) => JsonNode.Parse(_tray.Handle(json))!;

    [Fact]
    public void Status_reports_connection_and_switches()
    {
        _status.Set(ConnectionState.Online);
        var s = Ask("{\"op\":\"status\"}");
        Assert.True(s["ok"]!.GetValue<bool>());
        Assert.Equal("Online", s["connection"]!.GetValue<string>());
        Assert.False(s["locallyPaused"]!.GetValue<bool>());
        Assert.Equal("NGP", s["device"]!.GetValue<string>());
    }

    [Fact]
    public void Local_pause_blocks_remote_commands_and_resume_lifts_only_the_local_pause()
    {
        Assert.True(Ask("{\"op\":\"pause\"}")["locallyPaused"]!.GetValue<bool>());
        Assert.True(_e.Policy.DisabledLocally);
        Assert.False(Ask("{\"op\":\"resume\"}")["locallyPaused"]!.GetValue<bool>());
        Assert.False(_e.Policy.DisabledLocally);
    }

    [Fact]
    public void Resume_cannot_override_the_emergency_flag()
    {
        File.WriteAllText(_e.Paths.EmergencyFlagFile, "");
        var s = Ask("{\"op\":\"resume\"}");
        Assert.True(s["emergencyDisabled"]!.GetValue<bool>());
        Assert.True(_e.Policy.DisabledLocally);
    }

    [Theory]
    [InlineData("{\"op\":\"exec\"}")]
    [InlineData("{\"op\":\"shutdown\"}")]
    [InlineData("garbage")]
    [InlineData("[]")]
    public void Unknown_ops_and_junk_are_rejected(string line) => Assert.False(Ask(line)["ok"]!.GetValue<bool>());
}
