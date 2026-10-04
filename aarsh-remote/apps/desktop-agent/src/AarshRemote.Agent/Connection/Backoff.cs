namespace AarshRemote.Agent.Connection;

/// <summary>Exponential backoff with jitter: 1 s, 2 s, 4 s … capped at 60 s, each ±20 %.</summary>
internal sealed class Backoff(Random rng, TimeSpan? min = null, TimeSpan? max = null, double jitter = 0.2)
{
    private readonly TimeSpan _min = min ?? TimeSpan.FromSeconds(1);
    private readonly TimeSpan _max = max ?? TimeSpan.FromSeconds(60);
    private int _attempt;

    public TimeSpan Next()
    {
        var baseSeconds = Math.Min(_max.TotalSeconds, _min.TotalSeconds * Math.Pow(2, Math.Min(_attempt, 20)));
        _attempt++;
        var factor = 1 + (rng.NextDouble() * 2 - 1) * jitter;
        return TimeSpan.FromSeconds(Math.Min(_max.TotalSeconds * (1 + jitter), baseSeconds * factor));
    }

    public void Reset() => _attempt = 0;
}
