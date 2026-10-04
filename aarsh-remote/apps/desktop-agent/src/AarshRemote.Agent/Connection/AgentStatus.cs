namespace AarshRemote.Agent.Connection;

internal enum ConnectionState { NotPaired, Connecting, Online, Disconnected }

/// <summary>Current link state, read by the tray pipe and written by the connection loop.</summary>
internal sealed class AgentStatus
{
    private volatile int _state = (int)ConnectionState.Disconnected;
    public ConnectionState State => (ConnectionState)_state;
    public string? LastError { get; private set; }
    public event Action<ConnectionState>? Changed;

    public void Set(ConnectionState s, string? error = null)
    {
        LastError = error;
        if (Interlocked.Exchange(ref _state, (int)s) != (int)s) Changed?.Invoke(s);
    }
}

/// <summary>Wakes the reconnect delay early when the network (or power state) changes.</summary>
internal interface INetworkSignal
{
    Task WaitForChangeAsync(CancellationToken ct);
    void Pulse();
}

internal sealed class NetworkSignal : INetworkSignal, IDisposable
{
    private volatile TaskCompletionSource _tcs = New();
    private static TaskCompletionSource New() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    public NetworkSignal()
    {
        System.Net.NetworkInformation.NetworkChange.NetworkAvailabilityChanged += OnAvail;
        System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += OnAddr;
    }

    private void OnAvail(object? s, System.Net.NetworkInformation.NetworkAvailabilityEventArgs e) { if (e.IsAvailable) Pulse(); }
    private void OnAddr(object? s, EventArgs e) => Pulse();

    public void Pulse() => Interlocked.Exchange(ref _tcs, New()).TrySetResult();
    public Task WaitForChangeAsync(CancellationToken ct) => _tcs.Task.WaitAsync(ct);

    public void Dispose()
    {
        System.Net.NetworkInformation.NetworkChange.NetworkAvailabilityChanged -= OnAvail;
        System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged -= OnAddr;
    }
}
