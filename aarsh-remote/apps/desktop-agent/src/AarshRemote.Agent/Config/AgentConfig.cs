using System.Text.Json;
using System.Text.Json.Serialization;

namespace AarshRemote.Agent.Config;

/// <summary>Non-secret settings (config.json). The private key is NEVER stored here; see IdentityStore.</summary>
internal sealed class AgentConfig
{
    public string ServerUrl { get; set; } = "";
    public string DeviceName { get; set; } = Environment.MachineName;
    /// <summary>Server command-signing public key (base64, 32 bytes), pinned at pairing time.</summary>
    public string ServerCommandPublicKey { get; set; } = "";
    public bool Paired { get; set; }
    public int HeartbeatSeconds { get; set; } = 15;
    public int MetricsSeconds { get; set; } = 15;
    /// <summary>Pass /f to shutdown.exe. Off by default so unsaved Revit/BIM work is never force-closed.</summary>
    public bool ForcePowerActions { get; set; }

    [JsonIgnore] public bool IsUsable => Paired && ServerUrl.Length > 0 && ServerCommandPublicKey.Length > 0;
}

internal sealed class ConfigStore(AgentPaths paths)
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public AgentConfig Load()
    {
        if (!File.Exists(paths.ConfigFile)) return new AgentConfig();
        return JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(paths.ConfigFile), Json) ?? new AgentConfig();
    }

    public void Save(AgentConfig cfg) => AtomicFile.WriteAllText(paths.ConfigFile, JsonSerializer.Serialize(cfg, Json));
}

internal static class AtomicFile
{
    public static void WriteAllText(string path, string content) => WriteAllBytes(path, System.Text.Encoding.UTF8.GetBytes(content));

    public static void WriteAllBytes(string path, byte[] content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, content);
        File.Move(tmp, path, overwrite: true);
    }
}
