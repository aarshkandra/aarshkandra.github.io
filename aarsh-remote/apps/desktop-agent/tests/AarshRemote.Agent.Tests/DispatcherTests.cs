using System.Text.Json.Nodes;
using AarshRemote.Agent.Commands;
using AarshRemote.Agent.Safety;
using Xunit;

namespace AarshRemote.Agent.Tests;

public class DispatcherTests : IDisposable
{
    private readonly TestEnv _e = new();
    public void Dispose() => _e.Dispose();

    [Fact]
    public async Task Sleep_acks_first_then_announces_GOING_TO_SLEEP_before_suspending()
    {
        var order = new List<string>();
        var ch = new FakeChannel();
        _e.Power.OnSleep = () => { order.Add("power.sleep:events=" + string.Join(",", ch.Events)); return Task.CompletedTask; };
        var r = await _e.Dispatcher.HandleAsync(_e.Envelope("SLEEP"), default);
        Assert.True(r.Ok);
        Assert.Empty(_e.Power.Calls);                     // nothing happens until the ack has been sent
        await r.After!(ch, default);
        Assert.Equal(["power.sleep:events=GOING_TO_SLEEP"], order);
    }

    [Fact]
    public async Task Restart_and_shutdown_pass_the_typed_delay_only()
    {
        await _e.Run("RESTART", new JsonObject { ["delaySeconds"] = 5 });
        await _e.Run("SHUTDOWN");
        Assert.Equal(["restart:5", "shutdown:0"], _e.Power.Calls);
    }

    [Fact]
    public async Task Tampered_or_unsigned_commands_do_nothing()
    {
        var env = _e.Envelope("SLEEP"); env["cmd"] = "SHUTDOWN";
        var r = await _e.Dispatcher.HandleAsync(env, default);
        Assert.False(r.Ok); Assert.Equal("ENVELOPE_BADSIGNATURE", r.Error); Assert.Null(r.After);
        var unsigned = _e.Envelope("SLEEP"); unsigned.Remove("sig");
        Assert.Equal("ENVELOPE_MALFORMED", (await _e.Dispatcher.HandleAsync(unsigned, default)).Error);
        Assert.Empty(_e.Power.Calls);
    }

    [Fact]
    public async Task Command_for_another_device_is_refused()
    {
        var r = await _e.Dispatcher.HandleAsync(_e.Envelope("SLEEP", device: Guid.NewGuid().ToString()), default);
        Assert.Equal("ENVELOPE_WRONGDEVICE", r.Error);
    }

    [Fact]
    public async Task Expired_and_replayed_commands_are_refused()
    {
        var old = _e.Envelope("SLEEP", issuedAt: _e.Time.Unix - 100);
        Assert.Equal("ENVELOPE_EXPIRED", (await _e.Dispatcher.HandleAsync(old, default)).Error);
        var env = _e.Envelope("GET_STATUS");
        Assert.True((await _e.Dispatcher.HandleAsync(env, default)).Ok);
        var replay = await _e.Dispatcher.HandleAsync(env, default);
        Assert.False(replay.Ok); Assert.Equal("REPLAY", replay.Error);
    }

    [Fact]
    public async Task Emergency_flag_blocks_everything_including_resume_and_status()
    {
        File.WriteAllText(_e.Paths.EmergencyFlagFile, "");
        foreach (var cmd in new[] { "SLEEP", "RESTART", "SHUTDOWN", "PREPARE_CONNECT", "GET_STATUS", "GET_METRICS", "RESUME_REMOTE", "PAUSE_REMOTE", "DISCONNECT" })
        {
            var args = cmd == "PREPARE_CONNECT" ? new JsonObject { ["ttlSeconds"] = 60 } : cmd == "DISCONNECT" ? new JsonObject { ["sessionId"] = Guid.NewGuid().ToString() } : null;
            var r = await _e.Dispatcher.HandleAsync(_e.Envelope(cmd, args), default);
            Assert.Equal("REMOTE_DISABLED_LOCALLY", r.Error);
        }
        Assert.Empty(_e.Power.Calls); Assert.Empty(_e.Provider.Calls);
        File.Delete(_e.Paths.EmergencyFlagFile);
        Assert.True((await _e.Run("GET_STATUS")).Ok); // removing the flag (physically) restores normal operation
    }

    [Fact]
    public async Task Local_pause_cannot_be_lifted_remotely_but_remote_pause_can()
    {
        _e.State.SetLocallyPaused(true);
        Assert.Equal("REMOTE_DISABLED_LOCALLY", (await _e.Run("RESUME_REMOTE")).Error);
        Assert.Equal("REMOTE_DISABLED_LOCALLY", (await _e.Run("SLEEP")).Error);
        _e.State.SetLocallyPaused(false);

        Assert.True((await _e.Run("PAUSE_REMOTE")).Ok);
        Assert.True(_e.State.RemotePaused);
        Assert.Equal("REMOTE_PAUSED", (await _e.Run("SLEEP")).Error);
        Assert.Equal("REMOTE_PAUSED", (await _e.Run("RESTART")).Error);
        Assert.True((await _e.Run("GET_STATUS")).Ok);
        Assert.True((await _e.Run("RESUME_REMOTE")).Ok);
        Assert.False(_e.State.RemotePaused);
        Assert.Empty(_e.Power.Calls);
    }

    [Fact]
    public void Pause_state_persists_and_corrupt_state_fails_closed()
    {
        _e.State.SetRemotePaused(true); _e.State.SetLocallyPaused(true);
        var reloaded = new AgentState(_e.Paths);
        Assert.True(reloaded.RemotePaused); Assert.True(reloaded.LocallyPaused);
        File.WriteAllText(_e.Paths.StateFile, "{ not json");
        Assert.True(new AgentState(_e.Paths).LocallyPaused); // unreadable ⇒ stay locked down, don't silently re-enable
    }

    [Fact]
    public async Task Prepare_connect_returns_a_one_time_ticket()
    {
        var r = await _e.Run("PREPARE_CONNECT", new JsonObject { ["ttlSeconds"] = 120 });
        Assert.True(r.Ok);
        Assert.Equal("987654321", r.Data!["rustdeskId"]!.GetValue<string>());
        Assert.Equal("Sup3r-One-Time-Pw", r.Data["oneTimePassword"]!.GetValue<string>());
        Assert.Equal(["prepare:120"], _e.Provider.Calls);
    }

    [Fact]
    public async Task Provider_problems_become_stable_error_codes_without_leaking_details()
    {
        _e.Provider.Unavailable = true;
        Assert.Equal("REMOTE_ENGINE_UNAVAILABLE", (await _e.Run("PREPARE_CONNECT", new JsonObject { ["ttlSeconds"] = 60 })).Error);
        _e.Provider.Unavailable = false; _e.Provider.Throw = true;
        var r = await _e.Run("PREPARE_CONNECT", new JsonObject { ["ttlSeconds"] = 60 });
        Assert.Equal("COMMAND_FAILED", r.Error);
        Assert.DoesNotContain("secret-detail", r.Error);
    }

    [Fact]
    public async Task Disconnect_rotates_via_provider()
    {
        var sid = Guid.NewGuid().ToString();
        Assert.True((await _e.Run("DISCONNECT", new JsonObject { ["sessionId"] = sid })).Ok);
        Assert.Equal([$"end:{sid}"], _e.Provider.Calls);
    }

    [Theory]
    [InlineData("WAKE")]
    [InlineData("CONNECT")]
    public async Task Commands_meant_for_other_components_are_unsupported(string cmd)
    {
        var args = cmd == "WAKE" ? new JsonObject { ["mac"] = "AA:BB:CC:DD:EE:FF", ["broadcast"] = "192.168.1.255" } : null;
        Assert.Equal("UNSUPPORTED_COMMAND", (await _e.Run(cmd, args)).Error);
    }

    [Fact]
    public async Task Metrics_are_returned_in_the_wire_shape()
    {
        var r = await _e.Run("GET_METRICS");
        Assert.Equal(18, r.Data!["cpuPct"]!.GetValue<double>());
        Assert.Equal(100, r.Data["uptimeSec"]!.GetValue<long>());
    }

    [Fact]
    public void Policy_reports_blocked_states()
    {
        Assert.False(_e.Policy.Blocked);
        _e.State.SetRemotePaused(true);
        Assert.True(_e.Policy.Blocked); Assert.False(_e.Policy.DisabledLocally);
        _e.State.SetRemotePaused(false); File.WriteAllText(_e.Paths.EmergencyFlagFile, "");
        Assert.True(_e.Policy.DisabledLocally);
    }
}
