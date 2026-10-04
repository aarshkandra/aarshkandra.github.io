using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using AarshRemote.Agent.Ipc;
using Microsoft.Extensions.Logging;

namespace AarshRemote.Agent.Windows;

/// <summary>Named pipe \\.\pipe\AarshRemote.Agent: SYSTEM + Administrators full control, interactive (logged-on) users read/write.</summary>
[SupportedOSPlatform("windows")]
internal sealed class TrayPipeServer(TrayProtocol protocol, ILogger<TrayPipeServer> log)
{
    public const string PipeName = "AarshRemote.Agent";

    public async Task RunAsync(CancellationToken ct)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var server = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, 4, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
                await server.WaitForConnectionAsync(ct);
                _ = Task.Run(() => Serve(server, ct), CancellationToken.None);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                log.LogWarning(e, "Tray pipe error; retrying");
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
        }
    }

    private async Task Serve(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                var buf = new byte[1024];
                var n = await pipe.ReadAsync(buf, cts.Token);
                var line = Encoding.UTF8.GetString(buf, 0, n).Split('\n')[0];
                await pipe.WriteAsync(Encoding.UTF8.GetBytes(protocol.Handle(line) + "\n"), cts.Token);
            }
            catch (Exception e) when (e is IOException or OperationCanceledException) { }
        }
    }
}
