using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;
using AarshRemote.Agent.Protocol;

namespace AarshRemote.Agent.Tests;

/// <summary>Minimal in-process stand-in for the control server's /ws/agent: challenge → verify hello → ready, then runs a script.</summary>
internal sealed class FakeServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _cts = new();
    public int Port { get; }
    public string Origin => $"http://127.0.0.1:{Port}";
    public Uri Url => new(Origin);
    public byte[] AgentPublicKey { get; set; } = [];
    public string? OriginToClaim { get; set; }
    public Func<WebSocket, JsonObject, Task>? OnReady { get; set; }
    public List<JsonObject> Hellos { get; } = [];
    public List<bool> HelloSigOk { get; } = [];
    public List<JsonObject> Received { get; } = [];
    public int Connections;

    public FakeServer()
    {
        for (var attempt = 0; ; attempt++)
        {
            Port = Random.Shared.Next(20000, 40000);
            try { _listener.Prefixes.Add($"http://127.0.0.1:{Port}/"); _listener.Start(); break; }
            catch (HttpListenerException) when (attempt < 20) { _listener.Prefixes.Clear(); }
        }
        _ = Task.Run(AcceptLoop);
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); } catch (Exception e) when (e is HttpListenerException or ObjectDisposedException or InvalidOperationException) { return; }
            if (!ctx.Request.IsWebSocketRequest) { ctx.Response.StatusCode = 404; ctx.Response.Close(); continue; }
            _ = Task.Run(() => Serve(ctx));
        }
    }

    private async Task Serve(HttpListenerContext ctx)
    {
        Interlocked.Increment(ref Connections);
        var ws = (await ctx.AcceptWebSocketAsync(null)).WebSocket;
        try
        {
            var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            await Send(ws, new JsonObject { ["type"] = "challenge", ["nonce"] = nonce, ["serverOrigin"] = OriginToClaim ?? Origin, ["ts"] = ts });
            var hello = await Receive(ws);
            if (hello is null) return;
            Hellos.Add(hello);
            var sig = Convert.FromBase64String(hello["sig"]!.GetValue<string>());
            var ok = Ed25519.Verify(AgentPublicKey, Signing.HelloInput(nonce, hello["deviceUuid"]!.GetValue<string>(), OriginToClaim ?? Origin, ts), sig);
            HelloSigOk.Add(ok);
            if (!ok) { await ws.CloseAsync((WebSocketCloseStatus)4401, "bad signature", CancellationToken.None); return; }
            await Send(ws, new JsonObject { ["type"] = "ready", ["heartbeatSec"] = 15 });
            var reader = Task.Run(async () =>
            {
                while (await Receive(ws) is { } m)
                {
                    lock (Received) Received.Add(m);
                    if (m["type"]?.GetValue<string>() == "heartbeat") await Send(ws, new JsonObject { ["type"] = "heartbeat.ack" }); // like the real server
                }
            });
            if (OnReady is not null) await OnReady(ws, hello);
            await Task.WhenAny(reader, Task.Delay(Timeout.Infinite, _cts.Token));
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException or ObjectDisposedException or IOException) { }
        finally { ws.Dispose(); }
    }

    public static async Task Send(WebSocket ws, JsonObject o) =>
        await ws.SendAsync(Encoding.UTF8.GetBytes(o.ToJsonString()), WebSocketMessageType.Text, true, CancellationToken.None);

    public static async Task<JsonObject?> Receive(WebSocket ws)
    {
        var buf = new byte[65536];
        using var ms = new MemoryStream();
        WebSocketReceiveResult r;
        do
        {
            r = await ws.ReceiveAsync(buf, CancellationToken.None);
            if (r.MessageType == WebSocketMessageType.Close) return null;
            ms.Write(buf, 0, r.Count);
        } while (!r.EndOfMessage);
        return (JsonObject?)JsonNode.Parse(ms.ToArray());
    }

    public JsonObject[] Snapshot() { lock (Received) return Received.ToArray(); }

    public void Dispose() { _cts.Cancel(); _listener.Close(); }
}
