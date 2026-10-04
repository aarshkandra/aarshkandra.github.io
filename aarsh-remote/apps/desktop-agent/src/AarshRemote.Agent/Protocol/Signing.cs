using System.Text;

namespace AarshRemote.Agent.Protocol;

/// <summary>Signing inputs shared with the server (see packages/protocol/src/messages.ts and envelope.ts).</summary>
internal static class Signing
{
    public const string EnvelopeDomain = "aarsh-cmd-v1\n";

    public static byte[] HelloInput(string nonce, string deviceUuid, string serverOrigin, long ts) =>
        Encoding.UTF8.GetBytes($"aarsh-hello-v1\n{nonce}\n{deviceUuid}\n{serverOrigin}\n{ts}");

    public static byte[] PairingPollInput(string requestId, long ts) =>
        Encoding.UTF8.GetBytes($"aarsh-pairing-poll-v1\n{requestId}\n{ts}");

    public static string SignHello(byte[] seed, string nonce, string deviceUuid, string serverOrigin, long ts) =>
        Convert.ToBase64String(Ed25519.Sign(seed, HelloInput(nonce, deviceUuid, serverOrigin, ts)));
}
