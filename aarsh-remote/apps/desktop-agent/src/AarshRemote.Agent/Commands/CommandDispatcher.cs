using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using AarshRemote.Agent.Metrics;
using AarshRemote.Agent.Power;
using AarshRemote.Agent.Protocol;
using AarshRemote.Agent.Remote;
using AarshRemote.Agent.Safety;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent.Commands;

/// <summary>What the connection layer can do for a command handler's follow-up work.</summary>
internal interface IAgentChannel
{
    Task SendEventAsync(string name, CancellationToken ct);
}

internal sealed record CommandResult(string? CommandId, bool Ok, string? Error = null, JsonObject? Data = null, Func<IAgentChannel, CancellationToken, Task>? After = null)
{
    public static CommandResult Fail(string? id, string error) => new(id, false, error);
}

/// <summary>Remembers command ids until they expire so a captured envelope cannot be replayed within its (≤60 s) lifetime.</summary>
internal sealed class ReplayCache(TimeProvider time)
{
    private readonly ConcurrentDictionary<string, long> _seen = new();

    public bool TryAdd(string id, long expiresAtUnix)
    {
        var now = time.GetUtcNow().ToUnixTimeSeconds();
        foreach (var kv in _seen.Where(kv => kv.Value < now - EnvelopeVerifier.ClockSkewSeconds)) _seen.TryRemove(kv.Key, out _);
        return _seen.TryAdd(id, expiresAtUnix);
    }
}

/// <summary>
/// The only place commands are interpreted. Order matters: verify signature/expiry/device → replay → local safety switches →
/// closed switch on the allow-list. Nothing from a message is ever executed as a program, path, or shell string.
/// </summary>
internal sealed class CommandDispatcher(
    string deviceUuid, byte[] serverPublicKey, AgentState state, LocalAccessPolicy policy,
    IPowerController power, IMetricsCollector metrics, IRemoteDesktopProvider provider,
    ReplayCache replay, TimeProvider time, ILogger<CommandDispatcher> log)
{
    private static readonly TimeSpan PreSleepFlush = TimeSpan.FromMilliseconds(750);
    public TimeSpan SleepFlushDelay { get; init; } = PreSleepFlush;

    public async Task<CommandResult> HandleAsync(JsonNode? raw, CancellationToken ct)
    {
        var now = time.GetUtcNow().ToUnixTimeSeconds();
        var (cmd, err) = EnvelopeVerifier.Verify(raw, serverPublicKey, deviceUuid, now);
        if (cmd is null)
        {
            var id = (raw as JsonObject)?["id"] is JsonValue v && v.GetValueKind() == System.Text.Json.JsonValueKind.String && Guid.TryParse(v.GetValue<string>(), out _) ? v.GetValue<string>() : null;
            log.LogWarning("Rejected command envelope: {Reason}", err);
            return CommandResult.Fail(id, "ENVELOPE_" + err.ToString()!.ToUpperInvariant());
        }
        if (!replay.TryAdd(cmd.Id, cmd.ExpiresAt))
        {
            log.LogWarning("Rejected replayed command {CommandId}", cmd.Id);
            return CommandResult.Fail(cmd.Id, "REPLAY");
        }

        // Local switches win over any remote instruction, including RESUME_REMOTE.
        if (policy.DisabledLocally)
        {
            log.LogWarning("Refused {Command}: remote access disabled on this PC (emergency flag: {Emergency})", cmd.Cmd, policy.EmergencyActive);
            return CommandResult.Fail(cmd.Id, "REMOTE_DISABLED_LOCALLY");
        }
        if (state.RemotePaused && cmd.Cmd is not ("RESUME_REMOTE" or "PAUSE_REMOTE" or "GET_STATUS" or "DISCONNECT"))
        {
            log.LogWarning("Refused {Command}: remote access is paused", cmd.Cmd);
            return CommandResult.Fail(cmd.Id, "REMOTE_PAUSED");
        }

        log.LogInformation("Executing {Command} ({CommandId})", cmd.Cmd, cmd.Id);
        try
        {
            return cmd.Cmd switch
            {
                "SLEEP" => new CommandResult(cmd.Id, true, After: async (ch, t) =>
                {
                    await ch.SendEventAsync("GOING_TO_SLEEP", t); // lets the server show SLEEPING instead of OFFLINE
                    await Task.Delay(SleepFlushDelay, t);
                    await power.SleepAsync(t);
                }),
                "RESTART" => new CommandResult(cmd.Id, true, After: (_, t) => power.RestartAsync(Delay(cmd), t)),
                "SHUTDOWN" => new CommandResult(cmd.Id, true, After: (_, t) => power.ShutdownAsync(Delay(cmd), t)),
                "PREPARE_CONNECT" => await PrepareConnect(cmd, ct),
                "DISCONNECT" => await Disconnect(cmd, ct),
                "GET_STATUS" => new CommandResult(cmd.Id, true, Data: Status()),
                "GET_METRICS" => new CommandResult(cmd.Id, true, Data: metrics.Collect().ToJson()),
                "PAUSE_REMOTE" => Pause(cmd, true),
                "RESUME_REMOTE" => Pause(cmd, false),
                _ => CommandResult.Fail(cmd.Id, "UNSUPPORTED_COMMAND"), // WAKE / CONNECT are not for this agent
            };
        }
        catch (ProviderUnavailableException e)
        {
            log.LogWarning("{Command} failed: {Reason}", cmd.Cmd, e.Message);
            return CommandResult.Fail(cmd.Id, "REMOTE_ENGINE_UNAVAILABLE");
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            log.LogError(e, "{Command} failed", cmd.Cmd);
            return CommandResult.Fail(cmd.Id, "COMMAND_FAILED");
        }
    }

    private static int Delay(VerifiedCommand c) => c.Args["delaySeconds"] is { } n && JsonInt.TryGet(n, out var d) ? (int)d : 0;

    private async Task<CommandResult> PrepareConnect(VerifiedCommand c, CancellationToken ct)
    {
        JsonInt.TryGet(c.Args["ttlSeconds"], out var ttl);
        var ticket = await provider.PrepareHostAsync(TimeSpan.FromSeconds(ttl), ct);
        // The password goes into the ack only; it is never logged or written to disk by the agent.
        return new CommandResult(c.Id, true, Data: new JsonObject { ["rustdeskId"] = ticket.RemoteId, ["oneTimePassword"] = ticket.OneTimePassword });
    }

    private async Task<CommandResult> Disconnect(VerifiedCommand c, CancellationToken ct)
    {
        await provider.EndSessionAsync(c.Args["sessionId"]!.GetValue<string>(), ct);
        return new CommandResult(c.Id, true);
    }

    private CommandResult Pause(VerifiedCommand c, bool paused)
    {
        state.SetRemotePaused(paused);
        return new CommandResult(c.Id, true);
    }

    private JsonObject Status() => new()
    {
        ["version"] = AgentInfo.Version,
        ["remotePaused"] = state.RemotePaused,
        ["remoteDisabled"] = policy.DisabledLocally,
        ["engine"] = provider.Name,
    };
}

internal static class AgentInfo
{
    public static readonly string Version = typeof(AgentInfo).Assembly.GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : "0.0.0";
}
