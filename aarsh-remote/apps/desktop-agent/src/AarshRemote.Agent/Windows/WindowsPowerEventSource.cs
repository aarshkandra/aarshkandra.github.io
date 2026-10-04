using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using AarshRemote.Agent.Power;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent.Windows;

/// <summary>
/// Receives WM_POWERBROADCAST on a hidden top-level window (message-only windows do not get broadcasts) so the agent can
/// announce GOING_TO_SLEEP before the PC suspends, and reconnect immediately on resume. If anything here fails the agent
/// carries on without it: the server then simply sees OFFLINE instead of SLEEPING for locally-initiated sleeps.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsPowerEventSource(ILogger<WindowsPowerEventSource> log) : IPowerEventSource
{
    public event Action? Suspending;
    public event Action? Resumed;

    private const uint WmPowerBroadcast = 0x0218;
    private const int PbtApmSuspend = 0x4, PbtApmResumeSuspend = 0x7, PbtApmResumeAutomatic = 0x12;
    private delegate IntPtr WndProc(IntPtr hWnd, uint msg, UIntPtr wParam, IntPtr lParam);
    private WndProc? _proc; // keep alive for the lifetime of the window

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WndClassEx
    {
        public uint Size, Style; public WndProc Proc; public int ClsExtra, WndExtra; public IntPtr Instance, Icon, Cursor, Background;
        public string? Menu; public string ClassName; public IntPtr IconSm;
    }

    [StructLayout(LayoutKind.Sequential)] private struct Msg { public IntPtr Hwnd; public uint Message; public UIntPtr WParam; public IntPtr LParam; public uint Time; public int X, Y; }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ushort RegisterClassEx(ref WndClassEx c);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(uint exStyle, string cls, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProc(IntPtr h, uint m, UIntPtr w, IntPtr l);
    [DllImport("user32.dll")] private static extern int GetMessage(out Msg m, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Msg m);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref Msg m);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandle(string? name);

    public void Start()
    {
        var t = new Thread(Pump) { IsBackground = true, Name = "AarshRemote.PowerEvents" };
        t.Start();
    }

    private void Pump()
    {
        try
        {
            _proc = Callback;
            var inst = GetModuleHandle(null);
            var cls = new WndClassEx { Size = (uint)Marshal.SizeOf<WndClassEx>(), Proc = _proc, Instance = inst, ClassName = "AarshRemotePowerWindow" };
            if (RegisterClassEx(ref cls) == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            if (CreateWindowEx(0, cls.ClassName, "", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, inst, IntPtr.Zero) == IntPtr.Zero)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            while (GetMessage(out var m, IntPtr.Zero, 0, 0) > 0) { TranslateMessage(ref m); DispatchMessage(ref m); }
        }
        catch (Exception e)
        {
            log.LogWarning(e, "Power event monitoring is unavailable; locally-initiated sleep will appear as OFFLINE");
        }
    }

    private IntPtr Callback(IntPtr hWnd, uint msg, UIntPtr wParam, IntPtr lParam)
    {
        if (msg == WmPowerBroadcast)
        {
            try
            {
                switch ((int)wParam.ToUInt32())
                {
                    case PbtApmSuspend: Suspending?.Invoke(); break;
                    case PbtApmResumeSuspend or PbtApmResumeAutomatic: Resumed?.Invoke(); break;
                }
            }
            catch (Exception e) { log.LogWarning(e, "Power event handler failed"); }
            return (IntPtr)1; // TRUE
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
}
