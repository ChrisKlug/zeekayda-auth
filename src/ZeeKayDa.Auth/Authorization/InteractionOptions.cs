namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Paths of the host-owned interaction pages the authorization flow hands off to. ZeeKayDa owns
/// no interaction UI; each configured path is a page the host application builds and drives
/// through the corresponding interaction service.
/// </summary>
public sealed class InteractionOptions
{
    /// <summary>
    /// Gets or sets the host-relative path of the host's error page for authorization requests
    /// whose errors cannot be redirected to the client (phase-1 validation failures — unknown
    /// client or unregistered redirect URI). When <see langword="null"/> (the default), the
    /// framework renders a minimal unbranded error response itself.
    /// </summary>
    /// <remarks>
    /// Must be an absolute path within the host application (starting with <c>/</c>), without
    /// scheme, authority, query, or fragment. The redirect to this page carries only an opaque
    /// error identifier — the error details are read server-side via the error interaction
    /// service, never from the query string, which would leak into proxy logs and browser
    /// history.
    /// </remarks>
    public string? ErrorPath { get; set; }
}
