using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using AarshRemote.Agent.Commands;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Metrics;
using AarshRemote.Agent.Pairing;
using AarshRemote.Agent.Protocol;
using AarshRemote.Agent.Remote;
using AarshRemote.Agent.Safety;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent.Connection;

internal sealed record SessionOutcome(bool ReachedReady, int? CloseCode, string? Reason);

/// <summary>One authenticated WebSocket session to the control server: challenge → hello → ready → heartbeat/metrics/commands.</summary>
internal sealed class AgentSession(
    Uri serverUrl, AgentConfig config, AgentIdentity identity, CommandDispatcher dispatcher, IMetricsCollector metrics,
    LocalAccessPolicy policy, AgentState state, IRemoteDesktopProvider provider, TimeProvider time, ILogger<AgentSession> log,
    TimeSpan? deadAfter = null) : IAgentChannel
{
    private const int MaxMessageBytes = 64 * 1024;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly SemaphoreSlim _commandSlots = new(4, 4);
    private ClientWebSocket? _ws;
    private volatile bool _ready;
    private long _lastReceivedTicks = Environment.TickCount64;
    private int _remoteCloseCode = -1; // -1 = none received
    private void CaptureClose(int? code) => Interlocked.Exchange(ref _remoteCloseCode, code ?? 1005);
    private int? RemoteClose => Volatile.Read(ref _remoteCloseCode) is var c && c >= 0 ? c : null;

    public async Task<SessionOutcome> RunAsync(CancellationToken ct)
    {
        using var ws = new ClientWebSocket();
        ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
        _ws = ws;
        try
        {
            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connectCts.CancelAfter(TimeSpan.FromSeconds(15));
                await ws.ConnectAsync(ServerUrl.WebSocket(serverUrl), connectCts.Token);
            }

            // 1. challenge → hello. The origin we sign must be the one we were configured with (blocks cross-server relay).
            var challenge = await ReceiveAsync(ws, TimeSpan.FromSeconds(10), ct, CaptureClose);
            if (challenge?["type"]?.GetValue<string>() != "challenge") return Closed(ws, "no challenge");
            var origin = challenge["serverOrigin"]!.GetValue<string>();
            if (!string.Equals(origin.TrimEnd('/'), ServerUrl.Origin(serverUrl), StringComparison.OrdinalIgnoreCase))
            {
                log.LogError("Server presented origin {Origin}, expected {Expected}; refusing to authenticate", origin, ServerUrl.Origin(serverUrl));
                return new SessionOutcome(false, null, "origin mismatch");
            }
            var nonce = challenge["nonce"]!.GetValue<string>();
            var ts = challenge["ts"]!.GetValue<long>();
            var (ip, mac) = NetworkInfo.Primary();
            var rdId = await SafeDetect(ct);
            var info = new JsonObject { ["os"] = Truncate(RuntimeInformation.OSDescription, 200) };
            if (ip is not null) info["localIp"] = ip;
            if (mac is not null) info["mac"] = mac;
            if (rdId is { Length: > 0 and <= 32 }) info["rustdeskId"] = rdId;
            await SendAsync(new JsonObject
            {
                ["type"] = "hello", ["deviceUuid"] = identity.DeviceUuidString, ["kind"] = "DESKTOP", ["version"] = AgentInfo.Version,
                ["sig"] = Signing.SignHello(identity.Seed, nonce, identity.DeviceUuidString, origin, ts), ["info"] = info,
            }, ct);

            // 2. ready (or an error / close with a code)
            var reply = await ReceiveAsync(ws, TimeSpan.FromSeconds(10), ct, CaptureClose);
            if (reply?["type"]?.GetValue<string>() == "error") log.LogError("Server rejected this agent: {Code}", reply["code"]?.GetValue<string>());
            if (reply?["type"]?.GetValue<string>() != "ready") return Closed(ws, "no ready");
            _ready = true;
            log.LogInformation("Connected and authenticated to {Server} (device key {Fingerprint})", ServerUrl.Origin(serverUrl), identity.Fingerprint);

            // 3. steady state
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var tasks = new[] { ReceiveLoop(ws, cts.Token), HeartbeatLoop(cts.Token), MetricsLoop(cts.Token), WatchLoop(cts.Token), DeadPeerLoop(ws, cts.Token) };
            var first = await Task.WhenAny(tasks);
            var names = new[] { "receive", "heartbeat", "metrics", "watch", "deadpeer" };
            var firstInfo = $"{names[Array.IndexOf(tasks, first)]}:{first.Status}:{first.Exception?.GetBaseException().GetType().Name}";
            var wsCloseAtFirst = (int?)ws.CloseStatus;
            await cts.CancelAsync();
            try { await Task.WhenAll(tasks); } catch (Exception e) when (e is OperationCanceledException or WebSocketException) { }
            log.LogDebug("Session loops ended: first={First} remoteClose={Remote} wsCloseAtFirst={WsAtFirst} wsCloseNow={WsNow}", firstInfo, RemoteClose, wsCloseAtFirst, (int?)ws.CloseStatus);
            return Closed(ws, "session ended");
        }
        catch (Exception e) when (!ct.IsCancellationRequested && e is WebSocketException or HttpRequestException or IOException or OperationCanceledException)
        {
            return new SessionOutcome(_ready, RemoteClose ?? (ws.CloseStatus is { } cs ? (int)cs : null), e.Message);
        }
        finally
        {
            _ready = false;
            _ws = null;
            await TryClose(ws);
        }
    }

    public async Task SendEventAsync(string name, CancellationToken ct) =>
        await SendAsync(new JsonObject { ["type"] = "event", ["name"] = name }, ct);

    /// <summary>Called from the OS power thread just before suspend; bounded so it can never stall the system.</summary>
    public void TryAnnounceSleep()
    {
        if (!_ready) return;
        try { SendEventAsync("GOING_TO_SLEEP", CancellationToken.None).Wait(TimeSpan.FromSeconds(1)); }
        catch (Exception e) when (e is AggregateException or WebSocketException or InvalidOperationException) { }
    }

    private SessionOutcome Closed(ClientWebSocket ws, string why) => new(_ready, RemoteClose ?? (ws.CloseStatus is { } cs ? (int)cs : null), why);

    private async Task ReceiveLoop(ClientWebSocket ws, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var msg = await ReceiveAsync(ws, null, ct, CaptureClose);
            if (msg is null) return; // closed
            Interlocked.Exchange(ref _lastReceivedTicks, Environment.TickCount64);
            if (msg["type"]?.GetValue<string>() != "command") continue;
            await _commandSlots.WaitAsync(ct);
            _ = Task.Run(async () =>
            {
                try { await RunCommand(msg, ct); }
                catch (Exception e) when (e is not OutOfMemoryException) { log.LogError(e, "Command handling failed"); }
                finally { _commandSlots.Release(); }
            }, CancellationToken.None);
        }
    }

    private async Task RunCommand(JsonNode msg, CancellationToken ct)
    {
        var result = await dispatcher.HandleAsync(msg, ct);
        if (result.CommandId is not null)
        {
            var ack = new JsonObject { ["type"] = "ack", ["commandId"] = result.CommandId, ["ok"] = result.Ok };
            if (result.Error is not null) ack["error"] = result.Error;
            if (result.Data is not null) ack["data"] = result.Data;
            await SendAsync(ack, ct);
        }
        if (result.Ok && result.After is not null) await result.After(this, ct); // e.g. suspend/restart only AFTER the ack went out
    }

    /// <summary>
    /// Half-open links (Wi-Fi dropped, NAT mapping expired) never produce a close frame, and .NET 8 has no pong timeout.
    /// The server answers every heartbeat with a heartbeat.ack, so silence for 3 heartbeat periods means the link is dead.
    /// </summary>
    private async Task DeadPeerLoop(ClientWebSocket ws, CancellationToken ct)
    {
        var limit = deadAfter ?? TimeSpan.FromSeconds(Math.Max(1, config.HeartbeatSeconds) * 3);
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(Math.Clamp(limit.TotalMilliseconds / 6, 100, 5000)), time);
        while (await timer.WaitForNextTickAsync(ct))
        {
            if (Environment.TickCount64 - Interlocked.Read(ref _lastReceivedTicks) <= limit.TotalMilliseconds) continue;
            log.LogWarning("No data from the server for {Seconds:0}s; treating the connection as dead", limit.TotalSeconds);
            ws.Abort();
            return;
        }
    }

    private async Task HeartbeatLoop(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, config.HeartbeatSeconds)), time);
        do { await SendHeartbeat(ct); } while (await timer.WaitForNextTickAsync(ct));
    }

    private Task SendHeartbeat(CancellationToken ct) => SendAsync(new JsonObject
    {
        ["type"] = "heartbeat", ["uptimeSec"] = Environment.TickCount64 / 1000, ["remoteDisabled"] = policy.DisabledLocally,
    }, ct);

    private async Task MetricsLoop(CancellationToken ct)
    {
        if (config.MetricsSeconds <= 0) { await Task.Delay(Timeout.Infinite, ct); return; }
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(config.MetricsSeconds), time);
        while (await timer.WaitForNextTickAsync(ct))
        {
            if (policy.DisabledLocally) continue; // privacy: nothing but heartbeats while the owner at the PC has switched remote access off
            await SendAsync(new JsonObject { ["type"] = "metrics", ["metrics"] = metrics.Collect().ToJson() }, ct);
        }
    }

    /// <summary>Reports local safety-switch changes immediately and stops the remote engine when access is switched off.</summary>
    private async Task WatchLoop(CancellationToken ct)
    {
        var last = policy.DisabledLocally;
        var changed = new SemaphoreSlim(0);
        void OnChanged() => changed.Release();
        state.Changed += OnChanged;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.WhenAny(changed.WaitAsync(ct), Task.Delay(TimeSpan.FromSeconds(1), time, ct)); // poll the flag file, wake on tray changes
                var now = policy.DisabledLocally;
                if (now == last) continue;
                last = now;
                log.LogWarning("Remote access is now {State} on this PC", now ? "DISABLED" : "ENABLED");
                if (now) await provider.DisableAsync(ct);
                await SendEventAsync(now ? "REMOTE_DISABLED" : "REMOTE_ENABLED", ct);
                await SendHeartbeat(ct);
            }
        }
        finally { state.Changed -= OnChanged; }
    }

    internal async Task SendAsync(JsonObject msg, CancellationToken ct)
    {
        var ws = _ws ?? throw new InvalidOperationException("not connected");
        var bytes = Encoding.UTF8.GetBytes(msg.ToJsonString());
        await _sendLock.WaitAsync(ct);
        try
        {
            if (ws.State != WebSocketState.Open) throw new InvalidOperationException("socket not open");
            await ws.SendAsync(bytes, WebSocketMessageType.Text, true, ct);
        }
        finally { _sendLock.Release(); }
    }

    /// <summary>Reads one JSON text message (≤64 KB). Returns null if the peer closed.</summary>
    private static async Task<JsonNode?> ReceiveAsync(ClientWebSocket ws, TimeSpan? timeout, CancellationToken ct, Action<int?>? capture = null)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeout is { } t) cts.CancelAfter(t);
        var buffer = new byte[4096];
        using var ms = new MemoryStream();
        WebSocketReceiveResult r;
        do
        {
            r = await ws.ReceiveAsync(buffer, cts.Token);
            if (r.MessageType == WebSocketMessageType.Close)
            {
                // Capture the peer's close code NOW: cancelling the sibling loops afterwards aborts the socket and can clobber CloseStatus.
                capture?.Invoke(r.CloseStatus is { } cs ? (int)cs : null);
                return null;
            }
            ms.Write(buffer, 0, r.Count);
            if (ms.Length > MaxMessageBytes) throw new WebSocketException("message too large");
        } while (!r.EndOfMessage);
        try { return JsonNode.Parse(ms.ToArray()); }
        catch (System.Text.Json.JsonException) { return new JsonObject(); } // ignore junk, keep the session
    }

    private async Task<string?> SafeDetect(CancellationToken ct)
    {
        try { return await provider.DetectAsync(ct); }
        catch (Exception e) when (e is not OperationCanceledException) { log.LogWarning(e, "Remote engine detection failed"); return null; }
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n];

    private static async Task TryClose(ClientWebSocket ws)
    {
        try
        {
            if (ws.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                using var c = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "bye", c.Token);
            }
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException or ObjectDisposedException) { }
    }
}
