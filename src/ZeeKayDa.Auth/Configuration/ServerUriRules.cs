namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Yes/no checks shared by the issuer and the endpoint URI overrides: both must use HTTPS, except
/// that <c>AllowInsecureIssuer</c> admits HTTP to a loopback host for local development.
/// </summary>
internal static class ServerUriRules
{
    /// <summary>HTTPS, or HTTP when <paramref name="allowInsecure"/> is set.</summary>
    internal static bool IsSchemePermitted(Uri uri, bool allowInsecure)
        => IsHttps(uri) || (allowInsecure && IsHttp(uri));

    /// <summary>HTTP that <paramref name="allowInsecure"/> admits, but to a host that is not loopback.</summary>
    internal static bool IsInsecureNonLoopback(Uri uri, bool allowInsecure)
        => allowInsecure && IsHttp(uri) && !LoopbackHelper.IsLoopbackHost(uri.Host);

    private static bool IsHttps(Uri uri)
        => string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static bool IsHttp(Uri uri)
        => string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
}
