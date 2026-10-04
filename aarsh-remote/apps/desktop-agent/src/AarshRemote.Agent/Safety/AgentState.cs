using System.Text.Json;
using AarshRemote.Agent.Config;

namespace AarshRemote.Agent.Safety;

/// <summary>
/// Local privacy switches. Two independent pauses, deliberately:
/// RemotePaused can be set/cleared by the owner remotely (PAUSE_REMOTE/RESUME_REMOTE);
/// LocallyPaused is set only by someone at the PC (tray) and can NOT be cleared remotely.
/// Both persist across restarts.
/// </summary>
internal sealed class AgentState
{
    private sealed record Persisted(bool RemotePaused, bool LocallyPaused);

    private readonly AgentPaths _paths;
    private readonly object _lock = new();
    private bool _remotePaused;
    private bool _locallyPaused;

    public AgentState(AgentPaths paths)
    {
        _paths = paths;
        try
        {
            if (File.Exists(paths.StateFile) && JsonSerializer.Deserialize<Persisted>(File.ReadAllText(paths.StateFile)) is { } p)
                (_remotePaused, _locallyPaused) = (p.RemotePaused, p.LocallyPaused);
        }
        catch (Exception e) when (e is IOException or JsonException)
        {
            // Unreadable state fails closed: treat as locally paused rather than silently re-enabling remote access.
            _locallyPaused = true;
        }
    }

    public bool RemotePaused { get { lock (_lock) return _remotePaused; } }
    public bool LocallyPaused { get { lock (_lock) return _locallyPaused; } }
    public event Action? Changed;

    public void SetRemotePaused(bool v) => Update(() => _remotePaused = v);
    public void SetLocallyPaused(bool v) => Update(() => _locallyPaused = v);

    private void Update(Action mutate)
    {
        lock (_lock)
        {
            mutate();
            AtomicFile.WriteAllText(_paths.StateFile, JsonSerializer.Serialize(new Persisted(_remotePaused, _locallyPaused)));
        }
        Changed?.Invoke();
    }
}
