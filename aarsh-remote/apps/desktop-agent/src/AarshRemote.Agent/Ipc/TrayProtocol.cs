using System.Text.Json.Nodes;
using AarshRemote.Agent.Commands;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Connection;
using AarshRemote.Agent.Safety;

namespace AarshRemote.Agent.Ipc;

/// <summary>
/// Local control channel for the tray app (one JSON object per line). Deliberately tiny: status, and pause/resume of THIS PC's
/// remote access. It can switch remote access OFF but never override the emergency flag, and "resume" only lifts the local pause.
/// </summary>
internal sealed class TrayProtocol(AgentStatus status, LocalAccessPolicy policy, AgentState state, Func<AgentConfig> config, AgentPaths paths)
{
    public string Handle(string line)
    {
        try
        {
            var req = JsonNode.Parse(line) as JsonObject;
            switch (req?["op"]?.GetValue<string>())
            {
                case "status": break;
                case "pause": state.SetLocallyPaused(true); break;
                case "resume": state.SetLocallyPaused(false); break;
                default: return Error("unknown op");
            }
            return Status();
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException) { return Error("bad request"); }
    }

    private string Status() => new JsonObject
    {
        ["ok"] = true,
        ["version"] = AgentInfo.Version,
        ["connection"] = status.State.ToString(),
        ["lastError"] = status.LastError,
        ["locallyPaused"] = state.LocallyPaused,
        ["remotePaused"] = state.RemotePaused,
        ["emergencyDisabled"] = policy.EmergencyActive,
        ["server"] = config().ServerUrl,
        ["device"] = config().DeviceName,
        ["logsDir"] = paths.LogsDir,
        ["emergencyFlag"] = paths.EmergencyFlagFile,
    }.ToJsonString();

    private static string Error(string m) => new JsonObject { ["ok"] = false, ["error"] = m }.ToJsonString();
}
