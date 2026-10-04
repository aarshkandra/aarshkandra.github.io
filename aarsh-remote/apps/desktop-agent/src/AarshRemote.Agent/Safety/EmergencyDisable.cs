using AarshRemote.Agent.Config;

namespace AarshRemote.Agent.Safety;

/// <summary>
/// The physical-access kill switch: while disable_remote_access.flag exists, the agent refuses every command and the remote
/// engine is disabled. Nothing sent over the network can create, delete, or ignore this file's effect.
/// </summary>
internal sealed class EmergencyDisable(AgentPaths paths)
{
    public bool IsActive => File.Exists(paths.EmergencyFlagFile);
    public string FlagPath => paths.EmergencyFlagFile;
}

/// <summary>Combines every local reason remote access is off; reported to the server as "disabled on the PC".</summary>
internal sealed class LocalAccessPolicy(EmergencyDisable emergency, AgentState state)
{
    public bool EmergencyActive => emergency.IsActive;
    public bool DisabledLocally => emergency.IsActive || state.LocallyPaused;
    public bool Blocked => DisabledLocally || state.RemotePaused;
}
