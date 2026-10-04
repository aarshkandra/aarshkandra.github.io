using AarshRemote.Agent.Power;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent.Connection;

/// <summary>Keeps one session alive forever: reconnect with exponential backoff, cut short by network/power-resume signals.</summary>
internal sealed class ConnectionLoop(
    Func<AgentSession> newSession, AgentStatus status, INetworkSignal network, Backoff backoff, IPowerEventSource power, ILogger<ConnectionLoop> log)
{
    // After these the problem is not transient: slow down instead of hammering the server.
    private static readonly TimeSpan AuthFailedWait = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan RevokedWait = TimeSpan.FromMinutes(5);
    private volatile AgentSession? _active;

    public async Task RunAsync(CancellationToken ct)
    {
        power.Suspending += () => _active?.TryAnnounceSleep();
        power.Resumed += network.Pulse; // sockets are dead after resume; reconnect now instead of waiting out a backoff
        power.Start();

        while (!ct.IsCancellationRequested)
        {
            status.Set(ConnectionState.Connecting);
            var session = newSession();
            _active = session;
            SessionOutcome outcome;
            try { outcome = await session.RunAsync(ct); }
            catch (Exception) when (ct.IsCancellationRequested) { break; } // shutting down
            catch (Exception e)
            {
                log.LogError(e, "Session crashed");
                outcome = new SessionOutcome(false, null, e.GetType().Name);
            }
            finally { _active = null; }

            status.Set(ConnectionState.Disconnected, outcome.Reason);
            if (outcome.ReachedReady) backoff.Reset();

            var wait = outcome.CloseCode switch
            {
                4401 => AuthFailedWait,   // bad credentials / unknown device
                4403 => RevokedWait,      // revoked by the owner
                4426 => RevokedWait,      // agent too old: needs an update
                4409 => TimeSpan.FromSeconds(2), // replaced by a newer connection of ours
                _ => outcome.ReachedReady && outcome.CloseCode is null ? TimeSpan.FromSeconds(1) : backoff.Next(),
            };
            log.LogWarning("Disconnected ({Reason}, code {Code}); retrying in {Delay:0.0}s", outcome.Reason, outcome.CloseCode, wait.TotalSeconds);
            if (outcome.CloseCode == 4403) log.LogError("This device has been revoked. Re-pair it (pair --force) if that was unintended.");

            using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var signalled = network.WaitForChangeAsync(delayCts.Token);
            try { await Task.WhenAny(Task.Delay(wait, delayCts.Token), signalled); }
            catch (OperationCanceledException) { break; }
            await delayCts.CancelAsync();
            if (signalled.IsCompletedSuccessfully) backoff.Reset();
        }
        status.Set(ConnectionState.Disconnected);
    }
}
