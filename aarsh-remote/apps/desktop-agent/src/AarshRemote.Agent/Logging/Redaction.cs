using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;

namespace AarshRemote.Agent.Logging;

/// <summary>Wrap anything secret in this so it can never be rendered into a log line, even by accident.</summary>
internal sealed class SecretString(string value)
{
    public string Reveal() => value;
    public override string ToString() => "[redacted]";
}

/// <summary>Last line of defence: replaces the value of any log property whose name looks like a credential.</summary>
internal sealed partial class RedactingEnricher : ILogEventEnricher
{
    [GeneratedRegex("pass|token|secret|key|seed|totp|sig|otp|credential|authorization", RegexOptions.IgnoreCase)]
    private static partial Regex Sensitive();

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory factory)
    {
        foreach (var name in logEvent.Properties.Keys.Where(k => Sensitive().IsMatch(k)).ToList())
            logEvent.AddOrUpdateProperty(factory.CreateProperty(name, "[redacted]"));
    }
}
