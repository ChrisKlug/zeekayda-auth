namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// The framework's authentication scheme names a host may need to configure a handler with. The
/// framework owns these schemes; a host page never challenges or signs into them.
/// </summary>
public static class ZeeKayDaSchemes
{
    /// <summary>
    /// The scheme an external provider's handler signs the authenticated user into, for the
    /// framework to pick up when the user returns through <c>/connect/resume</c>.
    /// </summary>
    /// <remarks>
    /// A handler deriving from <c>RemoteAuthenticationHandler</c> — every provider package — has
    /// its sign-in scheme set to this by the framework, and the host names nothing. A handler
    /// written without that base class, whose author need know nothing of this framework, has a
    /// sign-in scheme option of its own; the host sets that option to this value when registering
    /// the handler through <c>WithProviders</c>, and the handler signs in there as it would into
    /// any cookie.
    /// </remarks>
    public const string External = "zkd.external";
}
