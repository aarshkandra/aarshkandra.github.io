using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace AarshRemote.Agent.Identity;

/// <summary>Protects small secrets at rest. Windows: DPAPI. Anything else is for development only (see InsecureDevProtector).</summary>
internal interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] protectedData);
    /// <summary>Tighten the file's permissions after it has been written (no-op where unsupported).</summary>
    void SecureFile(string path);
}

/// <summary>
/// DPAPI with LocalMachine scope, so the installer/pairing run (an administrator) and the service (LocalSystem) can both read it.
/// LocalMachine scope alone lets any local process decrypt, so the file is additionally restricted by ACL to SYSTEM + Administrators.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DpapiSecretProtector : ISecretProtector
{
    private static readonly byte[] Entropy = "AarshRemote.Identity.v1"u8.ToArray();

    public byte[] Protect(byte[] plaintext) => ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.LocalMachine);
    public byte[] Unprotect(byte[] protectedData) => ProtectedData.Unprotect(protectedData, Entropy, DataProtectionScope.LocalMachine);

    public void SecureFile(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false); // drop inherited ACEs (e.g. Users)
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }
}

/// <summary>
/// Development-only (non-Windows) storage that is NOT secure. It refuses to run unless AARSH_DEV_INSECURE_STORE=1 and never
/// activates on Windows, so a production install cannot fall back to it.
/// </summary>
internal sealed class InsecureDevProtector : ISecretProtector
{
    public InsecureDevProtector()
    {
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The insecure dev store is never used on Windows.");
        if (Environment.GetEnvironmentVariable("AARSH_DEV_INSECURE_STORE") != "1")
            throw new InvalidOperationException("No secure secret store on this OS. Set AARSH_DEV_INSECURE_STORE=1 for development only.");
    }

    public byte[] Protect(byte[] plaintext) => plaintext.ToArray();
    public byte[] Unprotect(byte[] protectedData) => protectedData.ToArray();

    public void SecureFile(string path)
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}

internal static class SecretProtectorFactory
{
    public static ISecretProtector Create() => OperatingSystem.IsWindows() ? new DpapiSecretProtector() : new InsecureDevProtector();
}
