namespace ZeeKayDa.Auth;

/// <summary>Derives published URIs from the issuer, shared by discovery and the ASP.NET Core routes.</summary>
internal static class IssuerUriHelper
{
    /// <summary>
    /// <paramref name="issuerUri"/> with a trailing slash, so <see cref="Uri(Uri, string)"/> appends
    /// to its last path segment rather than replacing it.
    /// </summary>
    public static Uri EnsureDirectoryBase(Uri issuerUri)
        => issuerUri.AbsolutePath.EndsWith('/')
            ? issuerUri
            : new Uri(issuerUri.AbsoluteUri + "/");

    /// <summary>Appends <paramref name="relativePath"/> to the issuer's full path.</summary>
    public static Uri Combine(Uri issuerUri, string relativePath)
        => new(EnsureDirectoryBase(issuerUri), relativePath);
}
