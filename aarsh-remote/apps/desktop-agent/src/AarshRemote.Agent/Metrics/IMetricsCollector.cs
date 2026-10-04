using System.Text.Json.Nodes;

namespace AarshRemote.Agent.Metrics;

/// <summary>Only what the dashboard shows. Every field is optional: a metric that cannot be read is simply omitted.</summary>
internal sealed record MetricsSnapshot(
    double? CpuPct = null, double? RamPct = null, double? GpuPct = null, double? DiskPct = null, double? TempC = null,
    double? NetRxKbps = null, double? NetTxKbps = null, long? UptimeSec = null, string? WindowsSession = null)
{
    /// <summary>Wire shape (strict schema on the server: unknown keys are rejected, nulls are omitted).</summary>
    public JsonObject ToJson()
    {
        var o = new JsonObject();
        void Add(string k, double? v) { if (v is { } d && double.IsFinite(d)) o[k] = Math.Round(d, 1); }
        Add("cpuPct", Clamp(CpuPct)); Add("ramPct", Clamp(RamPct)); Add("gpuPct", Clamp(GpuPct)); Add("diskPct", Clamp(DiskPct));
        Add("tempC", TempC); Add("netRxKbps", NetRxKbps is < 0 ? 0 : NetRxKbps); Add("netTxKbps", NetTxKbps is < 0 ? 0 : NetTxKbps);
        if (UptimeSec is { } u && u >= 0) o["uptimeSec"] = u;
        if (WindowsSession is "none" or "locked" or "active" or "disconnected") o["windowsSession"] = WindowsSession;
        return o;
    }

    private static double? Clamp(double? v) => v is { } d ? Math.Clamp(d, 0, 100) : null;
}

internal interface IMetricsCollector
{
    MetricsSnapshot Collect();
}

/// <summary>Portable fallback (dev/non-Windows): uptime and system-drive usage only.</summary>
internal sealed class MinimalMetricsCollector : IMetricsCollector
{
    public MetricsSnapshot Collect()
    {
        double? disk = null;
        try
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory) ?? "/";
            var d = new DriveInfo(root);
            if (d.TotalSize > 0) disk = 100.0 * (d.TotalSize - d.AvailableFreeSpace) / d.TotalSize;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { /* omit */ }
        return new MetricsSnapshot(DiskPct: disk, UptimeSec: Environment.TickCount64 / 1000);
    }
}
