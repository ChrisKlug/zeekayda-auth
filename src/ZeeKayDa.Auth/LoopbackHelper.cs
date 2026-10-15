using System.Net;

namespace ZeeKayDa.Auth;

/// <summary>The one loopback host and address check, shared by core and the ASP.NET Core layer.</summary>
internal static class LoopbackHelper
{
    /// <summary>Whether <paramref name="host"/>, as <see cref="Uri.Host"/> gives it, is <c>localhost</c> or a loopback IP.</summary>
    public static bool IsLoopbackHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return true;

        // Uri.Host keeps IPv6 brackets, which IPAddress.TryParse refuses.
        var hostToParse = host.StartsWith('[') && host.EndsWith(']')
            ? host[1..^1]
            : host;

        return IPAddress.TryParse(hostToParse, out var ip) && IPAddress.IsLoopback(ip);
    }

    /// <summary>Whether the connection's remote <paramref name="address"/> is known and loopback.</summary>
    public static bool IsLoopbackAddress(IPAddress? address)
        => address is not null && IPAddress.IsLoopback(address);
}
