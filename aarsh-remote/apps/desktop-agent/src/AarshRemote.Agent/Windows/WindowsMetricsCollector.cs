using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using AarshRemote.Agent.Metrics;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent.Windows;

/// <summary>
/// CPU (perf counter), RAM, system-drive usage, NIC throughput, session state, and — only if nvidia-smi exists — GPU load/temperature.
/// Every probe is isolated: one that fails is logged once and simply omitted from the snapshot.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsMetricsCollector : IMetricsCollector, IDisposable
{
    private readonly ILogger<WindowsMetricsCollector> _log;
    private readonly PerformanceCounter? _cpu;
    private readonly HashSet<string> _warned = [];
    private long _lastRx, _lastTx;
    private long _lastTicks = Stopwatch.GetTimestamp();
    private readonly string? _nvidiaSmi;

    public WindowsMetricsCollector(ILogger<WindowsMetricsCollector> log)
    {
        _log = log;
        try { _cpu = new PerformanceCounter("Processor Information", "% Processor Utility", "_Total"); _cpu.NextValue(); }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException) { Warn("cpu", e); }
        (_lastRx, _lastTx) = NicBytes();
        var smi = Path.Combine(Environment.SystemDirectory, "nvidia-smi.exe");
        _nvidiaSmi = File.Exists(smi) ? smi : null;
    }


    public MetricsSnapshot Collect()
    {
        double? cpu = Try("cpu", () => _cpu?.NextValue());
        double? ram = Try("ram", () =>
        {
            var m = new Native.MemoryStatusEx { Length = (uint)Marshal.SizeOf<Native.MemoryStatusEx>() };
            return Native.GlobalMemoryStatusEx(ref m) ? m.MemoryLoad : (double?)null;
        });
        double? disk = Try("disk", () =>
        {
            var d = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)!);
            return d.TotalSize > 0 ? 100.0 * (d.TotalSize - d.AvailableFreeSpace) / d.TotalSize : (double?)null;
        });
        var (rx, tx) = Try("net", ThroughputKbps);
        var (gpu, temp) = Try("gpu", ReadGpu);
        return new MetricsSnapshot(cpu, ram, gpu, disk, temp, rx, tx, Environment.TickCount64 / 1000, Try("session", Session));
    }

    private (double? rx, double? tx) ThroughputKbps()
    {
        var (rx, tx) = NicBytes();
        var now = Stopwatch.GetTimestamp();
        var secs = (now - _lastTicks) / (double)Stopwatch.Frequency;
        (double? rxKbps, double? txKbps) result = secs > 0 ? ((rx - _lastRx) * 8 / 1000 / secs, (tx - _lastTx) * 8 / 1000 / secs) : (null, null);
        (_lastRx, _lastTx, _lastTicks) = (rx, tx, now);
        return result;
    }

    private static (long rx, long tx) NicBytes()
    {
        long rx = 0, tx = 0;
        foreach (var n in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            var s = n.GetIPv4Statistics();
            rx += s.BytesReceived; tx += s.BytesSent;
        }
        return (rx, tx);
    }

    /// <summary>nvidia-smi with a fixed argument list; output is two numbers, parsed strictly.</summary>
    private (double? gpu, double? temp) ReadGpu()
    {
        if (_nvidiaSmi is null) return (null, null);
        var psi = new ProcessStartInfo(_nvidiaSmi) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in new[] { "--query-gpu=utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits" }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi);
        if (p is null) return (null, null);
        if (!p.WaitForExit(2000)) { p.Kill(); return (null, null); }
        var parts = p.StandardOutput.ReadLine()?.Split(',', StringSplitOptions.TrimEntries);
        return parts is { Length: 2 } && double.TryParse(parts[0], System.Globalization.CultureInfo.InvariantCulture, out var g) && double.TryParse(parts[1], System.Globalization.CultureInfo.InvariantCulture, out var t) ? (g, t) : (null, null);
    }

    private static string Session()
    {
        var id = Native.WTSGetActiveConsoleSessionId();
        if (id == 0xFFFFFFFF) return "none";
        if (!Native.WTSQuerySessionInformation(IntPtr.Zero, id, Native.WtsConnectState, out var buf, out _)) return "none";
        try { return Marshal.ReadInt32(buf) switch { 0 => "active", 4 => "disconnected", _ => "none" }; } // lock screen is still "active"; not detected
        finally { Native.WTSFreeMemory(buf); }
    }

    private T? Try<T>(string name, Func<T?> probe)
    {
        try { return probe(); }
        catch (Exception e) when (e is not OutOfMemoryException) { Warn(name, e); return default; }
    }

    private void Warn(string name, Exception e)
    {
        if (_warned.Add(name)) _log.LogWarning("Metric '{Metric}' unavailable: {Reason}", name, e.Message);
    }

    public void Dispose() => _cpu?.Dispose();
}
