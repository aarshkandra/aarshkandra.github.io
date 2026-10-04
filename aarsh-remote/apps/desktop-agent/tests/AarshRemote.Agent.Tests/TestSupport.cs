using System.Text;
using System.Text.Json.Nodes;
using AarshRemote.Agent.Commands;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Metrics;
using AarshRemote.Agent.Power;
using AarshRemote.Agent.Protocol;
using AarshRemote.Agent.Remote;
using AarshRemote.Agent.Safety;
using Microsoft.Extensions.Logging.Abstractions;

namespace AarshRemote.Agent.Tests;

internal sealed class FakeTime(long unix) : TimeProvider
{
    public long Unix { get; set; } = unix;
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Unix);
}

internal sealed class FakePower : IPowerController
{
    public List<string> Calls { get; } = [];
    public Func<Task>? OnSleep { get; set; }
    public Task SleepAsync(CancellationToken ct) { Calls.Add("sleep"); return OnSleep?.Invoke() ?? Task.CompletedTask; }
    public Task RestartAsync(int d, CancellationToken ct) { Calls.Add($"restart:{d}"); return Task.CompletedTask; }
    public Task ShutdownAsync(int d, CancellationToken ct) { Calls.Add($"shutdown:{d}"); return Task.CompletedTask; }
}

internal sealed class FakeProvider : IRemoteDesktopProvider
{
    public string Name => "fake";
    public bool Unavailable { get; set; }
    public bool Throw { get; set; }
    public List<string> Calls { get; } = [];
    public Task<string?> DetectAsync(CancellationToken ct) => Task.FromResult<string?>("987654321");
    public Task<HostTicket> PrepareHostAsync(TimeSpan ttl, CancellationToken ct)
    {
        Calls.Add($"prepare:{(int)ttl.TotalSeconds}");
        if (Unavailable) throw new ProviderUnavailableException("nope");
        if (Throw) throw new InvalidOperationException("boom with secret-detail");
        return Task.FromResult(new HostTicket("987654321", "Sup3r-One-Time-Pw"));
    }
    public Task EndSessionAsync(string sessionId, CancellationToken ct) { Calls.Add($"end:{sessionId}"); return Task.CompletedTask; }
    public Task DisableAsync(CancellationToken ct) { Calls.Add("disable"); return Task.CompletedTask; }
}

internal sealed class FakeMetrics : IMetricsCollector
{
    public MetricsSnapshot Collect() => new(CpuPct: 18, RamPct: 42, UptimeSec: 100);
}

internal sealed class FakeChannel : IAgentChannel
{
    public List<string> Events { get; } = [];
    public Func<List<string>>? Order { get; set; }
    public Task SendEventAsync(string name, CancellationToken ct) { Events.Add(name); return Task.CompletedTask; }
}

/// <summary>A temp data directory plus every collaborator the dispatcher needs, with a server key we control.</summary>
internal sealed class TestEnv : IDisposable
{
    public static readonly byte[] ServerSeed = Enumerable.Repeat((byte)1, 32).ToArray();
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "aarsh-agent-tests-" + Guid.NewGuid().ToString("N"));
    public AgentPaths Paths { get; }
    public string DeviceUuid { get; } = Guid.NewGuid().ToString();
    public FakeTime Time { get; } = new(1_800_000_000);
    public FakePower Power { get; } = new();
    public FakeProvider Provider { get; } = new();
    public AgentState State { get; }
    public EmergencyDisable Emergency { get; }
    public LocalAccessPolicy Policy { get; }
    public CommandDispatcher Dispatcher { get; }
    public byte[] ServerPublic => Ed25519.PublicKeyFromSeed(ServerSeed);

    public TestEnv()
    {
        Directory.CreateDirectory(Dir);
        Paths = new AgentPaths(Dir, Path.Combine(Dir, "disable_remote_access.flag"));
        State = new AgentState(Paths);
        Emergency = new EmergencyDisable(Paths);
        Policy = new LocalAccessPolicy(Emergency, State);
        Dispatcher = new CommandDispatcher(DeviceUuid, ServerPublic, State, Policy, Power, new FakeMetrics(), Provider, new ReplayCache(Time), Time, NullLogger<CommandDispatcher>.Instance)
        { SleepFlushDelay = TimeSpan.Zero };
    }

    public JsonObject Envelope(string cmd, JsonObject? args = null, string? id = null, long? issuedAt = null, int ttl = 30, string? device = null)
    {
        var iat = issuedAt ?? Time.Unix;
        var body = new JsonObject
        {
            ["id"] = id ?? Guid.NewGuid().ToString(), ["cmd"] = cmd, ["args"] = args ?? new JsonObject(), ["issuedAt"] = iat,
            ["expiresAt"] = iat + ttl, ["nonce"] = "AAAAAAAAAAAAAAAAAAAAAA==", ["deviceUuid"] = device ?? DeviceUuid,
        };
        var sig = Convert.ToBase64String(Ed25519.Sign(ServerSeed, Encoding.UTF8.GetBytes(Signing.EnvelopeDomain + Canonical.Serialize(body))));
        body["type"] = "command"; body["sig"] = sig;
        return body;
    }

    public async Task<CommandResult> Run(string cmd, JsonObject? args = null, FakeChannel? channel = null)
    {
        var r = await Dispatcher.HandleAsync(Envelope(cmd, args), CancellationToken.None);
        if (r.After is not null) await r.After(channel ?? new FakeChannel(), CancellationToken.None);
        return r;
    }

    public void Dispose() { try { Directory.Delete(Dir, true); } catch (IOException) { } }
}
