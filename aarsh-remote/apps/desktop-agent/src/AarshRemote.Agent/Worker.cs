using AarshRemote.Agent.Commands;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Connection;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Ipc;
using AarshRemote.Agent.Metrics;
using AarshRemote.Agent.Pairing;
using AarshRemote.Agent.Power;
using AarshRemote.Agent.Remote;
using AarshRemote.Agent.Safety;
using AarshRemote.Agent.Windows;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent;

/// <summary>The Windows service body: wait until paired, then keep the control connection alive until stopped.</summary>
internal sealed class Worker(
    AgentPaths paths, ConfigStore configStore, IdentityStore identityStore, AgentState state, AgentStatus status,
    ILoggerFactory loggers, ILogger<Worker> log) : BackgroundService
{
    private volatile AgentConfig _config = new();

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void StartTray(TrayPipeServer tray, CancellationToken ct) => _ = Task.Run(() => tray.RunAsync(ct), CancellationToken.None);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var emergency = new EmergencyDisable(paths);
        var policy = new LocalAccessPolicy(emergency, state);
        log.LogInformation("AarshRemote agent {Version} starting. Data dir {DataDir}", AgentInfo.Version, paths.DataDir);
        if (emergency.IsActive) log.LogWarning("Emergency disable flag present ({Flag}): remote access is OFF until it is removed", emergency.FlagPath);

        if (OperatingSystem.IsWindows())
        {
            var tray = new TrayPipeServer(new TrayProtocol(status, policy, state, () => _config, paths), loggers.CreateLogger<TrayPipeServer>());
            StartTray(tray, ct);
        }

        // Pairing normally happens before the service starts, but support doing it afterwards without a restart.
        AgentConfig cfg;
        while (!(cfg = configStore.Load()).IsUsable)
        {
            status.Set(ConnectionState.NotPaired, "not paired");
            log.LogWarning("This PC is not paired yet. Run: AarshRemote.Agent.exe pair --server https://<your-server>");
            try { await Task.Delay(TimeSpan.FromSeconds(15), ct); } catch (OperationCanceledException) { return; }
        }
        _config = cfg;

        var identity = identityStore.Load() ?? throw new InvalidOperationException("Config says paired but no device identity exists; run pair --force");
        var serverKey = Convert.FromBase64String(cfg.ServerCommandPublicKey);
        var serverUrl = ServerUrl.Validate(cfg.ServerUrl);
        var time = TimeProvider.System;

        IPowerController power = OperatingSystem.IsWindows() ? new WindowsPowerController(cfg.ForcePowerActions, loggers.CreateLogger<WindowsPowerController>()) : new DevPowerController(paths);
        IMetricsCollector metrics = OperatingSystem.IsWindows() ? new WindowsMetricsCollector(loggers.CreateLogger<WindowsMetricsCollector>()) : new MinimalMetricsCollector();
        IPowerEventSource powerEvents = OperatingSystem.IsWindows() ? new WindowsPowerEventSource(loggers.CreateLogger<WindowsPowerEventSource>()) : new NullPowerEventSource();
        IRemoteDesktopProvider provider = !OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("AARSH_DEV_FAKE_PROVIDER") == "1"
            ? new DevFakeRemoteDesktopProvider() : new NullRemoteDesktopProvider();

        var dispatcher = new CommandDispatcher(identity.DeviceUuidString, serverKey, state, policy, power, metrics, provider, new ReplayCache(time), time, loggers.CreateLogger<CommandDispatcher>());
        using var network = new NetworkSignal();
        var loop = new ConnectionLoop(
            () => new AgentSession(serverUrl, cfg, identity, dispatcher, metrics, policy, state, provider, time, loggers.CreateLogger<AgentSession>()),
            status, network, new Backoff(Random.Shared), powerEvents, loggers.CreateLogger<ConnectionLoop>());

        try { await loop.RunAsync(ct); }
        finally { log.LogInformation("AarshRemote agent stopping"); }
    }
}
