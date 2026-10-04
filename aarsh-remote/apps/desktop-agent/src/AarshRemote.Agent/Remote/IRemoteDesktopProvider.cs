namespace AarshRemote.Agent.Remote;

internal sealed record HostTicket(string RemoteId, string OneTimePassword);

internal sealed class ProviderUnavailableException(string message) : Exception(message);

/// <summary>
/// Host-side remote-desktop engine abstraction (mirrors IRemoteDesktopProvider in docs/architecture.md §5).
/// The RustDesk implementation arrives in Phase 5 after its CLI/config surface has been verified.
/// </summary>
internal interface IRemoteDesktopProvider
{
    string Name { get; }
    /// <summary>Remote ID to report to the server, if the engine is installed and running.</summary>
    Task<string?> DetectAsync(CancellationToken ct);
    /// <summary>Mint a fresh single-use credential valid for <paramref name="ttl"/>. Must replace any previous one.</summary>
    Task<HostTicket> PrepareHostAsync(TimeSpan ttl, CancellationToken ct);
    /// <summary>End a session and rotate the credential so the old one is useless.</summary>
    Task EndSessionAsync(string sessionId, CancellationToken ct);
    /// <summary>Stop accepting connections (emergency disable / local pause).</summary>
    Task DisableAsync(CancellationToken ct);
}

/// <summary>Used until a real engine is configured: every connect attempt fails with a clear reason.</summary>
internal sealed class NullRemoteDesktopProvider : IRemoteDesktopProvider
{
    public string Name => "none";
    public Task<string?> DetectAsync(CancellationToken ct) => Task.FromResult<string?>(null);
    public Task<HostTicket> PrepareHostAsync(TimeSpan ttl, CancellationToken ct) => throw new ProviderUnavailableException("No remote desktop engine is configured on this PC");
    public Task EndSessionAsync(string sessionId, CancellationToken ct) => Task.CompletedTask;
    public Task DisableAsync(CancellationToken ct) => Task.CompletedTask;
}

/// <summary>Development-only (non-Windows, AARSH_DEV_FAKE_PROVIDER=1): hands out random tickets so the connect flow can be exercised end to end.</summary>
internal sealed class DevFakeRemoteDesktopProvider : IRemoteDesktopProvider
{
    public DevFakeRemoteDesktopProvider()
    {
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The fake provider is development-only.");
    }

    public string Name => "dev-fake";
    public Task<string?> DetectAsync(CancellationToken ct) => Task.FromResult<string?>("123456789");
    public Task<HostTicket> PrepareHostAsync(TimeSpan ttl, CancellationToken ct) =>
        Task.FromResult(new HostTicket("123456789", Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12)).Replace('/', 'x').Replace('+', 'y')));
    public Task EndSessionAsync(string sessionId, CancellationToken ct) => Task.CompletedTask;
    public Task DisableAsync(CancellationToken ct) => Task.CompletedTask;
}
