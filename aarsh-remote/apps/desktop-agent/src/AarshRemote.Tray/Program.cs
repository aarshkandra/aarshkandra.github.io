using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json.Nodes;

namespace AarshRemote.Tray;

/// <summary>
/// Optional per-user tray icon. It only talks to the agent service over a local named pipe; the service works the same
/// without it. The tray can pause/resume THIS PC's remote access and open the logs, nothing more.
/// </summary>
internal static class Program
{
    private const string PipeName = "AarshRemote.Agent";

    [STAThread]
    private static void Main()
    {
        using var mutex = new Mutex(true, @"Local\AarshRemote.Tray", out var first);
        if (!first) return;
        ApplicationConfiguration.Initialize();
        using var ctx = new TrayContext();
        Application.Run(ctx);
    }

    internal static JsonNode? Ask(string op)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
            pipe.Connect(1000);
            pipe.Write(Encoding.UTF8.GetBytes($"{{\"op\":\"{op}\"}}\n"));
            var buf = new byte[8192];
            var n = pipe.Read(buf, 0, buf.Length);
            return JsonNode.Parse(Encoding.UTF8.GetString(buf, 0, n));
        }
        catch (Exception e) when (e is IOException or TimeoutException or System.Text.Json.JsonException or UnauthorizedAccessException) { return null; }
    }
}

internal sealed class TrayContext : ApplicationContext
{
    private readonly NotifyIcon _icon = new() { Visible = true, Text = "Aarsh Remote" };
    private readonly ToolStripMenuItem _state = new("Checking…") { Enabled = false };
    private readonly ToolStripMenuItem _pause = new("Pause remote access");
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 3000 };
    private string? _logs;
    private bool _paused;

    public TrayContext()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripLabel("Aarsh Remote") { Font = new Font(SystemFonts.MenuFont!, FontStyle.Bold) });
        menu.Items.Add(_state);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_pause);
        menu.Items.Add("View logs", null, (_, _) => { if (_logs is not null) Process.Start(new ProcessStartInfo(_logs) { UseShellExecute = true }); });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit tray (service keeps running)", null, (_, _) => ExitThread());
        _pause.Click += (_, _) => { Refresh(Program.Ask(_paused ? "resume" : "pause")); };
        _icon.ContextMenuStrip = menu;
        _icon.Icon = SystemIcons.Shield;
        _timer.Tick += (_, _) => Refresh(Program.Ask("status"));
        _timer.Start();
        Refresh(Program.Ask("status"));
    }

    private void Refresh(JsonNode? s)
    {
        if (s is null || s["ok"]?.GetValue<bool>() != true)
        {
            _state.Text = "● Agent service not running";
            _pause.Enabled = false;
            _icon.Text = "Aarsh Remote: agent not running";
            return;
        }
        _logs = s["logsDir"]?.GetValue<string>();
        _paused = s["locallyPaused"]?.GetValue<bool>() == true;
        var emergency = s["emergencyDisabled"]?.GetValue<bool>() == true;
        var conn = s["connection"]?.GetValue<string>() ?? "Unknown";
        _state.Text = emergency ? "● Disabled (emergency flag present)" : _paused ? "● Remote access paused" : $"● {conn}";
        _pause.Text = _paused ? "Resume remote access" : "Pause remote access";
        _pause.Enabled = !emergency;
        _icon.Text = $"Aarsh Remote: {(emergency ? "disabled" : _paused ? "paused" : conn)}";
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _timer.Dispose(); _icon.Visible = false; _icon.Dispose(); }
        base.Dispose(disposing);
    }
}
