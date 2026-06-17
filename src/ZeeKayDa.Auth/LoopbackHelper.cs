using System.Net;

namespace ZeeKayDa.Auth;

/// <summary>
/// Internal helpers for detecting loopback hosts and addresses.
/// </summary>
/// <remarks>
/// Lives in the core <c>ZeeKayDa.Auth</c> assembly so that both the redirect-URI validator
/// and the ASP.NET Core endpoint route helper share a single, authoritative loopback-detection
/// implementation. Exposed to <c>ZeeKayDa.Auth.AspNetCore</c> and test projects via the
/// <c>InternalsVisibleTo</c> declarations in <c>ZeeKayDaAuth.cs</c>.
/// </remarks>
internal static class LoopbackHelper
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="host"/> resolves to a loopback
    /// address — i.e. the literal <c>localhost</c> hostname or an IPv4/IPv6 loopback address
    /// (with or without surrounding brackets).
    /// </summary>
    /// <param name="host">
    /// The host portion of a URI as returned by <see cref="Uri.Host"/>, e.g.
    /// <c>"localhost"</c>, <c>"127.0.0.1"</c>, or <c>"[::1]"</c>.
    /// </param>
    public static bool IsLoopbackHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return true;

        // Strip IPv6 brackets for parsing — Uri.Host preserves them, but IPAddress.TryParse
        // requires bare addresses.
        var hostToParse = host.StartsWith('[') && host.EndsWith(']')
            ? host[1..^1]
            : host;

        return IPAddress.TryParse(hostToParse, out var ip) && IPAddress.IsLoopback(ip);
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="address"/> is a non-null loopback
    /// address, as determined by <see cref="IPAddress.IsLoopback"/>.
    /// </summary>
    /// <param name="address">
    /// The remote <see cref="IPAddress"/> from the current HTTP connection, or
    /// <see langword="null"/> if the address is unavailable.
    /// </param>
    public static bool IsLoopbackAddress(IPAddress? address)
        => address is not null && IPAddress.IsLoopback(address);
}
