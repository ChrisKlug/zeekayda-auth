namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// How a failure message repeats a configured URI: never with its user information, query or
/// fragment, which may hold a secret and are never redacted.
/// </summary>
internal static class ConfiguredUri
{
    /// <summary>Whether the URI has no user information, query or fragment to keep out of a message.</summary>
    public static bool CanShowVerbatim(Uri parsed) =>
        parsed.UserInfo.Length == 0 && parsed.Query.Length == 0 && parsed.Fragment.Length == 0;

    /// <summary>
    /// The configured value verbatim when <see cref="CanShowVerbatim"/>; otherwise only its scheme,
    /// host, port and path.
    /// </summary>
    public static string Display(string configured, Uri parsed) =>
        CanShowVerbatim(parsed)
            ? configured
            : parsed.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped);
}
