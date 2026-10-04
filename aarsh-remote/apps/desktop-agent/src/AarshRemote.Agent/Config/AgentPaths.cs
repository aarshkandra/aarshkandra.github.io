namespace AarshRemote.Agent.Config;

/// <summary>All on-disk locations. Overridable by environment for tests/dev only.</summary>
internal sealed class AgentPaths
{
    public string DataDir { get; }
    public string LogsDir => Path.Combine(DataDir, "Logs");
    public string ConfigFile => Path.Combine(DataDir, "config.json");
    public string StateFile => Path.Combine(DataDir, "state.json");
    public string IdentityFile => Path.Combine(DataDir, "identity.bin");
    public string EmergencyFlagFile { get; }

    public AgentPaths(string dataDir, string emergencyFlagFile)
    {
        DataDir = dataDir;
        EmergencyFlagFile = emergencyFlagFile;
    }

    /// <summary>C:\ProgramData\AarshRemote and C:\Program Files\AarshRemote\disable_remote_access.flag by default.</summary>
    public static AgentPaths FromEnvironment()
    {
        var data = Environment.GetEnvironmentVariable("AARSH_DATA_DIR")
                   ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AarshRemote");
        var flag = Environment.GetEnvironmentVariable("AARSH_EMERGENCY_FLAG")
                   ?? Path.Combine(AppContext.BaseDirectory, "disable_remote_access.flag");
        return new AgentPaths(data, flag);
    }
}
