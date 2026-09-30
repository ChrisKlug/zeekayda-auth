namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// How a configuration failure repeats a URI the host configured. A failure message is printed
/// with the startup error, where nothing redacts it, so a URI's user information, query and
/// fragment (a password, a signed token) never appear in it.
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
