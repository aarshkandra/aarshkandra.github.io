using System.Diagnostics;
using System.Runtime.Versioning;
using AarshRemote.Agent.Power;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent.Windows;

/// <summary>
/// Restart/shutdown via the system's shutdown.exe with a FIXED argument list (only the integer delay varies), no shell.
/// Unsaved work is protected: /f (force-close apps) is only added when the owner enabled ForcePowerActions in config.json.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsPowerController(bool force, ILogger<WindowsPowerController> log) : IPowerController
{
    private static readonly string ShutdownExe = Path.Combine(Environment.SystemDirectory, "shutdown.exe");

    public Task RestartAsync(int delaySeconds, CancellationToken ct) => Shutdown("/r", delaySeconds, "Aarsh Remote: restart requested");
    public Task ShutdownAsync(int delaySeconds, CancellationToken ct) => Shutdown("/s", delaySeconds, "Aarsh Remote: shutdown requested");

    private Task Shutdown(string mode, int delaySeconds, string comment)
    {
        var psi = new ProcessStartInfo(ShutdownExe) { UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(mode);
        psi.ArgumentList.Add("/t"); psi.ArgumentList.Add(Math.Clamp(delaySeconds, 0, 60).ToString(System.Globalization.CultureInfo.InvariantCulture));
        psi.ArgumentList.Add("/c"); psi.ArgumentList.Add(comment);
        if (force) psi.ArgumentList.Add("/f");
        log.LogWarning("Running shutdown.exe {Mode} (delay {Delay}s, force {Force})", mode, delaySeconds, force);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("could not start shutdown.exe");
        return Task.CompletedTask;
    }

    public Task SleepAsync(CancellationToken ct)
    {
        Native.EnablePrivilege("SeShutdownPrivilege");
        // hibernate=false → S3 sleep; disableWakeEvent=false → wake events (Wake-on-LAN) stay armed.
        if (!Native.SetSuspendState(false, false, false))
            throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
        return Task.CompletedTask;
    }
}
