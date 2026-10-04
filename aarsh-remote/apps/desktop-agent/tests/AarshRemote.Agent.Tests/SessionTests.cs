using System.Net.WebSockets;
using System.Text.Json.Nodes;
using AarshRemote.Agent.Commands;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Connection;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Power;
using AarshRemote.Agent.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AarshRemote.Agent.Tests;

public class SessionTests : IDisposable
{
    private readonly TestEnv _e = new();
    private readonly FakeServer _srv = new();
    private readonly AgentIdentity _id;

    public SessionTests()
    {
        _id = new IdentityStore(_e.Paths, new NoopProtector()).Create();
        _srv.AgentPublicKey = _id.PublicKey;
    }

    public void Dispose() { _srv.Dispose(); _e.Dispose(); }

    private sealed class NoopProtector : ISecretProtector
    {
        public byte[] Protect(byte[] p) => p; public byte[] Unprotect(byte[] p) => p; public void SecureFile(string path) { }
    }

    private AgentSession NewSession(int heartbeat = 1, int metrics = 1)
    {
        var dispatcher = new CommandDispatcher(_id.DeviceUuidString, _e.ServerPublic, _e.State, _e.Policy, _e.Power, new FakeMetrics(), _e.Provider,
            new ReplayCache(TimeProvider.System), TimeProvider.System, NullLogger<CommandDispatcher>.Instance) { SleepFlushDelay = TimeSpan.Zero };
        var cfg = new AgentConfig { HeartbeatSeconds = heartbeat, MetricsSeconds = metrics };
        return new AgentSession(_srv.Url, cfg, _id, dispatcher, new FakeMetrics(), _e.Policy, _e.State, _e.Provider, TimeProvider.System, NullLogger<AgentSession>.Instance,
            deadAfter: TimeSpan.FromSeconds(3));
    }

    private JsonObject Signed(string cmd, JsonObject? args = null) => _e.Envelope(cmd, args, device: _id.DeviceUuidString, issuedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    private static async Task Until(Func<bool> cond, int ms = 5000)
    {
        var end = Environment.TickCount64 + ms;
        while (!cond()) { if (Environment.TickCount64 > end) throw new TimeoutException("condition not met"); await Task.Delay(20); }
    }

    [Fact]
    public async Task Handshake_proves_possession_of_the_key_and_reports_heartbeats_and_metrics()
    {
        using var cts = new CancellationTokenSource();
        var run = NewSession().RunAsync(cts.Token);
        await Until(() => _srv.Snapshot().Any(m => m["type"]!.GetValue<string>() == "metrics"));
        var hello = _srv.Hellos.Single();
        Assert.True(_srv.HelloSigOk.Single());
        Assert.Equal("DESKTOP", hello["kind"]!.GetValue<string>());
        Assert.Equal(_id.DeviceUuidString, hello["deviceUuid"]!.GetValue<string>());
        Assert.Matches(@"^\d+\.\d+\.\d+$", hello["version"]!.GetValue<string>());
        Assert.Contains(_srv.Snapshot(), m => m["type"]!.GetValue<string>() == "heartbeat");
        var metrics = _srv.Snapshot().First(m => m["type"]!.GetValue<string>() == "metrics")["metrics"]!;
        Assert.Equal(18, metrics["cpuPct"]!.GetValue<double>());
        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task Refuses_to_authenticate_to_a_server_that_claims_a_different_origin()
    {
        _srv.OriginToClaim = "https://evil.example";
        var outcome = await NewSession().RunAsync(CancellationToken.None);
        Assert.False(outcome.ReachedReady);
        Assert.Equal("origin mismatch", outcome.Reason);
        Assert.Empty(_srv.Hellos); // never sent a signature to the wrong server
    }

    [Fact]
    public async Task Executes_signed_commands_acks_before_acting_and_rejects_forged_ones()
    {
        var acks = new List<JsonObject>();
        _srv.OnReady = async (ws, _) =>
        {
            await FakeServer.Send(ws, Signed("RESTART", new JsonObject { ["delaySeconds"] = 3 }));
            var forged = Signed("SHUTDOWN"); forged["cmd"] = "SLEEP";
            await FakeServer.Send(ws, forged);
        };
        using var cts = new CancellationTokenSource();
        var run = NewSession(heartbeat: 30, metrics: 0).RunAsync(cts.Token);
        await Until(() => _srv.Snapshot().Count(m => m["type"]!.GetValue<string>() == "ack") >= 2);
        acks.AddRange(_srv.Snapshot().Where(m => m["type"]!.GetValue<string>() == "ack"));
        Assert.Contains(acks, a => a["ok"]!.GetValue<bool>());
        Assert.Contains(acks, a => !a["ok"]!.GetValue<bool>() && a["error"]!.GetValue<string>() == "ENVELOPE_BADSIGNATURE");
        await Until(() => _e.Power.Calls.Count == 1);
        Assert.Equal(["restart:3"], _e.Power.Calls); // the forged SLEEP never ran
        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task Sleep_command_announces_GOING_TO_SLEEP_after_the_ack()
    {
        _srv.OnReady = async (ws, _) => await FakeServer.Send(ws, Signed("SLEEP"));
        using var cts = new CancellationTokenSource();
        var run = NewSession(heartbeat: 30, metrics: 0).RunAsync(cts.Token);
        await Until(() => _e.Power.Calls.Contains("sleep"));
        var types = _srv.Snapshot().Select(m => m["type"]!.GetValue<string>() + (m["name"] is { } n ? ":" + n.GetValue<string>() : "")).ToList();
        Assert.True(types.IndexOf("ack") < types.IndexOf("event:GOING_TO_SLEEP"), string.Join(",", types));
        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task Reports_the_emergency_flag_within_a_second_and_stops_the_engine()
    {
        using var cts = new CancellationTokenSource();
        var run = NewSession(heartbeat: 30, metrics: 0).RunAsync(cts.Token);
        await Until(() => _srv.Hellos.Count == 1);
        File.WriteAllText(_e.Paths.EmergencyFlagFile, "");
        await Until(() => _srv.Snapshot().Any(m => m["type"]!.GetValue<string>() == "event" && m["name"]!.GetValue<string>() == "REMOTE_DISABLED"), 4000);
        Assert.Contains(_srv.Snapshot(), m => m["type"]!.GetValue<string>() == "heartbeat" && m["remoteDisabled"]!.GetValue<bool>());
        Assert.Contains("disable", _e.Provider.Calls);
        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task Server_close_codes_survive_even_while_the_agent_is_busy_sending()
    {
        // Regression: cancelling sibling loops after a close frame used to be able to clobber the status (seen as 1000 instead of 4403).
        _srv.OnReady = async (ws, _) => { await Task.Delay(Random.Shared.Next(0, 40)); await ws.CloseAsync((WebSocketCloseStatus)4403, "revoked", CancellationToken.None); };
        for (var i = 0; i < 25; i++)
        {
            var outcome = await NewSession(heartbeat: 1, metrics: 1).RunAsync(CancellationToken.None);
            Assert.Equal(4403, outcome.CloseCode);
            Assert.True(outcome.ReachedReady);
        }
    }

    [Fact]
    public async Task A_dead_peer_with_no_close_handshake_is_detected_by_the_watchdog()
    {
        _srv.OnReady = (ws, _) => { ws.Abort(); return Task.CompletedTask; };
        var run = NewSession(heartbeat: 30, metrics: 0).RunAsync(CancellationToken.None);
        var done = await Task.WhenAny(run, Task.Delay(8000));
        Assert.Same(run, done); // without the watchdog this never returns
        Assert.True((await run).ReachedReady);
    }

    [Fact]
    public async Task Loop_reconnects_after_a_drop_and_backs_off_for_a_long_time_when_revoked()
    {
        var drop = true;
        _srv.OnReady = async (ws, _) =>
        {
            if (drop) { drop = false; ws.Abort(); }
            else await ws.CloseAsync((WebSocketCloseStatus)4403, "revoked", CancellationToken.None);
        };
        var status = new AgentStatus();
        var loop = new ConnectionLoop(() => NewSession(), status, new NetworkSignal(), new Backoff(new Random(1), TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(200)), new NullPowerEventSource(), NullLogger<ConnectionLoop>.Instance);
        using var cts = new CancellationTokenSource();
        var run = loop.RunAsync(cts.Token);
        await Until(() => _srv.Connections >= 2, 8000);          // reconnected on its own after the drop
        await Task.Delay(1200);
        Assert.Equal(2, _srv.Connections);                        // 4403 ⇒ minutes of backoff, not a retry storm
        Assert.Equal(ConnectionState.Disconnected, status.State);
        await cts.CancelAsync();
        await run;
    }
}
