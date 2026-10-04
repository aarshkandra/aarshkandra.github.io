using System.Text.Json.Nodes;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Connection;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Logging;
using AarshRemote.Agent.Metrics;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace AarshRemote.Agent.Tests;

public class BackoffTests
{
    [Fact]
    public void Grows_exponentially_with_jitter_and_caps_at_60_seconds()
    {
        var b = new Backoff(new Random(1));
        var delays = Enumerable.Range(0, 12).Select(_ => b.Next().TotalSeconds).ToList();
        for (var i = 0; i < 6; i++) Assert.InRange(delays[i], Math.Pow(2, i) * 0.8, Math.Pow(2, i) * 1.2);
        Assert.All(delays.Skip(6), d => Assert.InRange(d, 48, 72));
        b.Reset();
        Assert.InRange(b.Next().TotalSeconds, 0.8, 1.2);
    }
}

public class IdentityTests : IDisposable
{
    private readonly TestEnv _e = new();
    public void Dispose() => _e.Dispose();

    /// <summary>Stand-in for DPAPI: visibly transforms bytes so we can assert the seed is not stored in the clear.</summary>
    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] p) => p.Select(b => (byte)(b ^ 0x5A)).ToArray();
        public byte[] Unprotect(byte[] p) => Protect(p);
        public void SecureFile(string path) { }
    }

    [Fact]
    public void Creates_once_reloads_identically_and_never_overwrites()
    {
        var store = new IdentityStore(_e.Paths, new XorProtector());
        Assert.Null(store.Load());
        var a = store.Create();
        var b = store.Load()!;
        Assert.Equal(a.DeviceUuid, b.DeviceUuid);
        Assert.Equal(a.PublicKey, b.PublicKey);
        Assert.Throws<InvalidOperationException>(() => store.Create());
        Assert.Equal(a.DeviceUuid, store.LoadOrCreate().DeviceUuid);
    }

    [Fact]
    public void Seed_is_not_present_in_plaintext_on_disk_nor_in_ToString()
    {
        var store = new IdentityStore(_e.Paths, new XorProtector());
        var id = store.Create();
        var file = File.ReadAllBytes(_e.Paths.IdentityFile);
        var seedB64 = Convert.ToBase64String(id.Seed);
        Assert.DoesNotContain(seedB64, System.Text.Encoding.UTF8.GetString(file));
        Assert.DoesNotContain(seedB64, id.ToString());
        Assert.True(id.Sign([1, 2, 3]).Length == 64);
    }

    [Fact]
    public void Dev_store_refuses_to_run_without_the_explicit_opt_in()
    {
        if (OperatingSystem.IsWindows()) return;
        Environment.SetEnvironmentVariable("AARSH_DEV_INSECURE_STORE", null);
        Assert.Throws<InvalidOperationException>(() => new InsecureDevProtector());
    }

    [Fact]
    public void Config_round_trips_and_never_contains_key_material()
    {
        var store = new ConfigStore(_e.Paths);
        store.Save(new AgentConfig { ServerUrl = "https://r.example", DeviceName = "NGP", Paired = true, ServerCommandPublicKey = "abc=" });
        var text = File.ReadAllText(_e.Paths.ConfigFile);
        Assert.DoesNotContain("seed", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private", text, StringComparison.OrdinalIgnoreCase);
        var c = store.Load();
        Assert.True(c.IsUsable); Assert.False(c.ForcePowerActions);
        Assert.False(new AgentConfig().IsUsable);
    }
}

public class RedactionTests
{
    private sealed class Capture : ILogEventSink
    {
        public List<LogEvent> Events { get; } = [];
        public void Emit(LogEvent e) => Events.Add(e);
    }

    [Fact]
    public void Credential_looking_properties_and_SecretString_never_reach_the_sink()
    {
        var sink = new Capture();
        using var log = new LoggerConfiguration().Enrich.With(new RedactingEnricher()).WriteTo.Sink(sink).CreateLogger();
        log.Information("hello {Password} {RefreshToken} {OneTimePassword} {PrivateKey} {Device}", "hunter2", "tok-123", "otp-9", "k", "NGP");
        log.Information("wrapped {Thing}", new SecretString("super-secret"));
        var rendered = string.Join("\n", sink.Events.Select(e => e.RenderMessage()));
        foreach (var leaked in new[] { "hunter2", "tok-123", "otp-9", "super-secret" }) Assert.DoesNotContain(leaked, rendered);
        Assert.Contains("NGP", rendered);
    }
}

public class MetricsTests
{
    [Fact]
    public void Wire_shape_clamps_omits_nulls_and_drops_invalid_values()
    {
        var j = new MetricsSnapshot(CpuPct: 140, RamPct: -3, GpuPct: null, NetRxKbps: -5, UptimeSec: 7, WindowsSession: "weird").ToJson();
        Assert.Equal(100, j["cpuPct"]!.GetValue<double>());
        Assert.Equal(0, j["ramPct"]!.GetValue<double>());
        Assert.Equal(0, j["netRxKbps"]!.GetValue<double>());
        Assert.Null(j["gpuPct"]); Assert.Null(j["windowsSession"]);
        Assert.Equal(7, j["uptimeSec"]!.GetValue<long>());
        Assert.True(new MetricsSnapshot(DiskPct: double.NaN).ToJson().Count == 0);
    }

    [Fact]
    public void Minimal_collector_works_anywhere()
    {
        var m = new MinimalMetricsCollector().Collect();
        Assert.NotNull(m.UptimeSec);
    }
}
