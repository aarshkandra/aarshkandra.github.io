using System.Net.Http.Json;
using System.Text.Json;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Protocol;

namespace AarshRemote.Agent.Pairing;

internal sealed class PairingException(string message) : Exception(message);

internal sealed record ServerInfo(string Origin, string CommandPublicKey, string MinAgentVersion);
internal sealed record PairingRequest(string RequestId, string Code, DateTimeOffset ExpiresAt);

internal static class ServerUrl
{
    /// <summary>TLS is mandatory. Plain http is accepted only for localhost and only with AARSH_ALLOW_INSECURE_HTTP=1 (development).</summary>
    public static Uri Validate(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) throw new PairingException("Server URL is not a valid URL");
        var isLocal = u.IsLoopback;
        var devHttp = u.Scheme == Uri.UriSchemeHttp && isLocal && Environment.GetEnvironmentVariable("AARSH_ALLOW_INSECURE_HTTP") == "1";
        if (u.Scheme != Uri.UriSchemeHttps && !devHttp) throw new PairingException("Server URL must use https://");
        if (!string.IsNullOrEmpty(u.UserInfo) || !string.IsNullOrEmpty(u.Query) || !string.IsNullOrEmpty(u.Fragment)) throw new PairingException("Server URL must not contain credentials, query or fragment");
        return new Uri(u.GetLeftPart(UriPartial.Authority));
    }

    /// <summary>Origin string exactly as the server states it in its challenge (scheme://host[:port], no trailing slash).</summary>
    public static string Origin(Uri u) => u.GetLeftPart(UriPartial.Authority).TrimEnd('/');

    public static Uri WebSocket(Uri baseUrl) =>
        new UriBuilder(baseUrl) { Scheme = baseUrl.Scheme == Uri.UriSchemeHttps ? "wss" : "ws", Path = "/ws/agent" }.Uri;
}

internal sealed class PairingClient(HttpClient http, TimeProvider time)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<ServerInfo> GetServerInfoAsync(Uri baseUrl, CancellationToken ct)
    {
        var r = await Send(() => http.GetAsync(new Uri(baseUrl, "/api/v1/server-info"), ct));
        var info = await r.Content.ReadFromJsonAsync<ServerInfo>(Json, ct) ?? throw new PairingException("Empty server-info response");
        if (Convert.FromBase64String(info.CommandPublicKey).Length != 32) throw new PairingException("Server returned an invalid command-signing key");
        return info;
    }

    public async Task<PairingRequest> RequestAsync(Uri baseUrl, AgentIdentity id, string name, CancellationToken ct)
    {
        var body = new { deviceUuid = id.DeviceUuidString, name, kind = "DESKTOP", publicKey = Convert.ToBase64String(id.PublicKey) };
        var r = await Send(() => http.PostAsJsonAsync(new Uri(baseUrl, "/api/v1/pairing/requests"), body, Json, ct));
        return await r.Content.ReadFromJsonAsync<PairingRequest>(Json, ct) ?? throw new PairingException("Empty pairing response");
    }

    /// <summary>Returns "paired" | "expired" | "burned" (never "pending"). Polls with a signature proving possession of the registered key.</summary>
    public async Task<string> WaitAsync(Uri baseUrl, AgentIdentity id, PairingRequest req, TimeSpan pollEvery, CancellationToken ct)
    {
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var ts = time.GetUtcNow().ToUnixTimeSeconds();
            using var msg = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUrl, $"/api/v1/pairing/requests/{req.RequestId}"));
            msg.Headers.Add("X-Timestamp", ts.ToString());
            msg.Headers.Add("X-Signature", Convert.ToBase64String(id.Sign(Signing.PairingPollInput(req.RequestId, ts))));
            var r = await Send(() => http.SendAsync(msg, ct));
            using var doc = JsonDocument.Parse(await r.Content.ReadAsStringAsync(ct));
            var status = doc.RootElement.GetProperty("status").GetString();
            if (status is "paired" or "expired" or "burned") return status;
            await Task.Delay(pollEvery, time, ct);
        }
    }

    private static async Task<HttpResponseMessage> Send(Func<Task<HttpResponseMessage>> call)
    {
        HttpResponseMessage r;
        try { r = await call(); }
        catch (HttpRequestException e) { throw new PairingException($"Cannot reach the server: {e.Message}"); }
        if (r.IsSuccessStatusCode) return r;
        string code = r.StatusCode.ToString();
        try { using var d = JsonDocument.Parse(await r.Content.ReadAsStringAsync()); code = d.RootElement.GetProperty("error").GetProperty("code").GetString() ?? code; } catch (Exception e) when (e is JsonException or KeyNotFoundException) { }
        throw new PairingException($"Server refused the request ({(int)r.StatusCode} {code})");
    }
}

/// <summary>The "agent install → pairing screen" flow (architecture §9.3).</summary>
internal static class PairCommand
{
    public static async Task<int> RunAsync(string server, string deviceName, bool force, AgentPaths paths, IdentityStore ids, ConfigStore cfgStore,
        PairingClient client, TextWriter output, TimeSpan pollEvery, CancellationToken ct)
    {
        try
        {
            var baseUrl = ServerUrl.Validate(server);
            var existing = cfgStore.Load();
            if (existing.Paired && !force)
            {
                output.WriteLine($"This PC is already paired with {existing.ServerUrl}. Use --force to pair again (creates a new device identity).");
                return 0;
            }
            if (force)
            {
                if (File.Exists(paths.IdentityFile)) File.Delete(paths.IdentityFile);
                if (File.Exists(paths.ConfigFile)) File.Delete(paths.ConfigFile);
            }
            var id = ids.LoadOrCreate();

            // Pin the server's command-signing key now, over TLS, before the user trusts this device to it.
            var info = await client.GetServerInfoAsync(baseUrl, ct);
            if (!string.Equals(info.Origin.TrimEnd('/'), ServerUrl.Origin(baseUrl), StringComparison.OrdinalIgnoreCase))
                throw new PairingException($"The server identifies as {info.Origin}, not {ServerUrl.Origin(baseUrl)}. Check its SERVER_ORIGIN setting.");

            var req = await client.RequestAsync(baseUrl, id, deviceName, ct);
            output.WriteLine("Device Pairing");
            output.WriteLine();
            output.WriteLine($"Device: {deviceName}");
            output.WriteLine();
            output.WriteLine("Request ID:");
            output.WriteLine(req.RequestId);
            output.WriteLine();
            output.WriteLine("Pairing Code:");
            output.WriteLine(req.Code);
            output.WriteLine();
            output.WriteLine($"Enter both in Aarsh Remote on your laptop (while logged in with two-factor). Expires {req.ExpiresAt.ToLocalTime():HH:mm}.");
            output.WriteLine("Waiting for pairing…");

            switch (await client.WaitAsync(baseUrl, id, req, pollEvery, ct))
            {
                case "paired":
                    cfgStore.Save(new AgentConfig { ServerUrl = ServerUrl.Origin(baseUrl), DeviceName = deviceName, ServerCommandPublicKey = info.CommandPublicKey, Paired = true });
                    output.WriteLine($"Paired. Device identity {id.Fingerprint}. The agent service will connect automatically.");
                    return 0;
                case "burned":
                    output.WriteLine("Too many wrong attempts; the code was cancelled. Run pairing again.");
                    return 2;
                default:
                    output.WriteLine("The pairing code expired. Run pairing again.");
                    return 2;
            }
        }
        catch (PairingException e)
        {
            output.WriteLine($"Pairing failed: {e.Message}");
            return 1;
        }
    }
}
