using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace AarshRemote.Agent.Connection;

/// <summary>Best-effort primary LAN address and MAC, reported once at connect so the owner can fill in Wake-on-LAN settings.</summary>
internal static class NetworkInfo
{
    public static (string? Ip, string? Mac) Primary()
    {
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                .Where(n => n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any)))
                .OrderBy(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet ? 0 : 1)
                .FirstOrDefault();
            if (nic is null) return (null, null);
            var ip = nic.GetIPProperties().UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString();
            var raw = nic.GetPhysicalAddress().GetAddressBytes();
            var mac = raw.Length == 6 ? string.Join(":", raw.Select(b => b.ToString("X2"))) : null;
            return (ip, mac);
        }
        catch (Exception e) when (e is NetworkInformationException or PlatformNotSupportedException) { return (null, null); }
    }
}
