namespace ZeeKayDa.Auth;

/// <summary>
/// Internal helpers for deriving published URIs from an issuer base.
/// </summary>
/// <remarks>
/// Lives in the core <c>ZeeKayDa.Auth</c> assembly so that both the discovery document
/// provider and the ASP.NET Core endpoint route helper share a single implementation of
/// the "ensure trailing slash, then <see cref="Uri"/>-combine" pattern. Combining a base
/// <see cref="Uri"/> with a relative path replaces the final path segment unless the base
/// ends with a slash, so this helper normalises that before combining.
/// </remarks>
internal static class IssuerUriHelper
{
    /// <summary>
    /// Returns <paramref name="issuerUri"/> as a directory-style <see cref="Uri"/> — i.e.
    /// guaranteed to end with a trailing slash so it can be used as the base argument to
    /// <see cref="Uri(Uri, string)"/> without replacing the final path segment.
    /// </summary>
    public static Uri EnsureDirectoryBase(Uri issuerUri)
        => issuerUri.AbsolutePath.EndsWith('/')
            ? issuerUri
            : new Uri(issuerUri.AbsoluteUri + "/");

    /// <summary>
    /// Combines <paramref name="issuerUri"/> with the supplied <paramref name="relativePath"/>
    /// using <see cref="Uri"/> semantics. The base is normalised to a directory first so the
    /// relative path is appended to the issuer's full path rather than replacing its last
    /// segment.
    /// </summary>
    public static Uri Combine(Uri issuerUri, string relativePath)
        => new(EnsureDirectoryBase(issuerUri), relativePath);
}
