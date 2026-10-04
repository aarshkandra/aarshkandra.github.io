using System.Text.Json;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Protocol;

namespace AarshRemote.Agent.Identity;

/// <summary>The device's cryptographic identity: a random UUID (not a credential) and an Ed25519 key.</summary>
internal sealed class AgentIdentity(Guid deviceUuid, byte[] seed)
{
    public Guid DeviceUuid { get; } = deviceUuid;
    public string DeviceUuidString => DeviceUuid.ToString();
    public byte[] PublicKey { get; } = Ed25519.PublicKeyFromSeed(seed);
    public string Fingerprint => Ed25519.Fingerprint(PublicKey);
    public byte[] Sign(byte[] data) => Ed25519.Sign(seed, data);
    internal byte[] Seed => seed;
    public override string ToString() => $"AgentIdentity({DeviceUuid}, key {Fingerprint})"; // never prints the key
}

internal sealed class IdentityStore(AgentPaths paths, ISecretProtector protector)
{
    private sealed record Stored(Guid DeviceUuid, string Seed);

    public bool Exists => File.Exists(paths.IdentityFile);

    public AgentIdentity? Load()
    {
        if (!Exists) return null;
        var plain = protector.Unprotect(File.ReadAllBytes(paths.IdentityFile));
        try
        {
            var s = JsonSerializer.Deserialize<Stored>(plain) ?? throw new InvalidDataException("identity file is empty");
            return new AgentIdentity(s.DeviceUuid, Convert.FromBase64String(s.Seed));
        }
        finally
        {
            Array.Clear(plain);
        }
    }

    public AgentIdentity Create()
    {
        if (Exists) throw new InvalidOperationException("An identity already exists; refusing to overwrite it.");
        var seed = Ed25519.NewSeed();
        var id = new AgentIdentity(Guid.NewGuid(), seed);
        var plain = JsonSerializer.SerializeToUtf8Bytes(new Stored(id.DeviceUuid, Convert.ToBase64String(seed)));
        try
        {
            AtomicFile.WriteAllBytes(paths.IdentityFile, protector.Protect(plain));
            protector.SecureFile(paths.IdentityFile);
        }
        finally
        {
            Array.Clear(plain);
        }
        return id;
    }

    public AgentIdentity LoadOrCreate() => Load() ?? Create();
}
