using AarshRemote.Agent;
using AarshRemote.Agent.Commands;
using AarshRemote.Agent.Config;
using AarshRemote.Agent.Connection;
using AarshRemote.Agent.Identity;
using AarshRemote.Agent.Logging;
using AarshRemote.Agent.Pairing;
using AarshRemote.Agent.Safety;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

var paths = AgentPaths.FromEnvironment();
var verb = args.FirstOrDefault()?.ToLowerInvariant();

switch (verb)
{
    case "--version" or "version":
        Console.WriteLine(AgentInfo.Version);
        return 0;
    case "pair":
        return await Pair(args.Skip(1).ToArray());
    case "status":
        return Status();
    case "help" or "--help" or "-h":
        Console.WriteLine("""
            AarshRemote.Agent [run]                          run the agent (the Windows service runs this)
            AarshRemote.Agent pair --server URL [--name N] [--force]   register this PC and show the pairing code
            AarshRemote.Agent status                         show identity fingerprint and pairing state
            AarshRemote.Agent version
            """);
        return 0;
    case null or "run":
        return await Run(args);
    default:
        Console.Error.WriteLine($"Unknown command '{verb}'. Try: help");
        return 64;
}

async Task<int> Pair(string[] a)
{
    string? Opt(string name) { var i = Array.IndexOf(a, name); return i >= 0 && i + 1 < a.Length ? a[i + 1] : null; }
    var server = Opt("--server");
    if (server is null) { Console.Error.WriteLine("--server https://your-server is required"); return 64; }
    var protector = SecretProtectorFactory.Create();
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
    try
    {
        return await PairCommand.RunAsync(server, Opt("--name") ?? Environment.MachineName, a.Contains("--force"), paths,
            new IdentityStore(paths, protector), new ConfigStore(paths), new PairingClient(http, TimeProvider.System), Console.Out, TimeSpan.FromSeconds(2), cts.Token);
    }
    catch (OperationCanceledException) { Console.WriteLine("Cancelled."); return 130; }
}

int Status()
{
    var cfg = new ConfigStore(paths).Load();
    var id = new IdentityStore(paths, SecretProtectorFactory.Create()).Load();
    Console.WriteLine($"Version:        {AgentInfo.Version}");
    Console.WriteLine($"Data dir:       {paths.DataDir}");
    Console.WriteLine($"Device UUID:    {id?.DeviceUuidString ?? "(none)"}");
    Console.WriteLine($"Key fingerprint:{(id is null ? " (none)" : " " + id.Fingerprint)}");
    Console.WriteLine($"Paired:         {cfg.Paired} ({(cfg.ServerUrl.Length > 0 ? cfg.ServerUrl : "no server")})");
    Console.WriteLine($"Emergency flag: {(new EmergencyDisable(paths).IsActive ? "ACTIVE - remote access disabled" : "not set")} ({paths.EmergencyFlagFile})");
    return 0;
}

async Task<int> Run(string[] a)
{
    Directory.CreateDirectory(paths.LogsDir);
    var serilog = new LoggerConfiguration()
        .MinimumLevel.Information()
        .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
        .Enrich.With(new RedactingEnricher())
        .WriteTo.File(Path.Combine(paths.LogsDir, "agent-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14,
            outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
        .WriteTo.Console()
        .CreateLogger();
    try
    {
        var builder = Host.CreateApplicationBuilder(a);
        builder.Services.AddWindowsService(o => o.ServiceName = "AarshRemoteAgent");
        builder.Logging.ClearProviders();
        builder.Logging.AddSerilog(serilog, dispose: true);
        builder.Services.AddSingleton(paths);
        builder.Services.AddSingleton<ConfigStore>();
        builder.Services.AddSingleton(SecretProtectorFactory.Create());
        builder.Services.AddSingleton<IdentityStore>();
        builder.Services.AddSingleton<AgentState>();
        builder.Services.AddSingleton<AgentStatus>();
        builder.Services.AddHostedService<Worker>();
        await builder.Build().RunAsync();
        return 0;
    }
    catch (Exception e)
    {
        serilog.Fatal(e, "Agent terminated unexpectedly");
        return 1;
    }
    finally { await Log.CloseAndFlushAsync(); }
}
