using AarshRemote.Agent.Config;

namespace AarshRemote.Agent.Power;

/// <summary>Power actions the agent may perform. Arguments are typed integers only; nothing from the network is ever a command line.</summary>
internal interface IPowerController
{
    Task SleepAsync(CancellationToken ct);
    Task RestartAsync(int delaySeconds, CancellationToken ct);
    Task ShutdownAsync(int delaySeconds, CancellationToken ct);
}

/// <summary>Non-Windows development stand-in: records what would have happened instead of touching the machine.</summary>
internal sealed class DevPowerController(AgentPaths paths) : IPowerController
{
    public Task SleepAsync(CancellationToken ct) => Record("sleep");
    public Task RestartAsync(int delaySeconds, CancellationToken ct) => Record($"restart delay={delaySeconds}");
    public Task ShutdownAsync(int delaySeconds, CancellationToken ct) => Record($"shutdown delay={delaySeconds}");

    private Task Record(string what)
    {
        Directory.CreateDirectory(paths.DataDir);
        File.AppendAllText(Path.Combine(paths.DataDir, "power-actions.log"), $"{DateTimeOffset.UtcNow:O} {what}{Environment.NewLine}");
        return Task.CompletedTask;
    }
}

/// <summary>Raised around system suspend/resume so the server can tell SLEEPING from OFFLINE.</summary>
internal interface IPowerEventSource
{
    event Action? Suspending;
    event Action? Resumed;
    void Start();
}

internal sealed class NullPowerEventSource : IPowerEventSource
{
    public event Action? Suspending { add { } remove { } }
    public event Action? Resumed { add { } remove { } }
    public void Start() { }
}
