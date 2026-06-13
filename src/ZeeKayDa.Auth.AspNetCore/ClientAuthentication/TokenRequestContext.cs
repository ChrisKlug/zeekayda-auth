using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Holds the request-shape information available to an <see cref="IClientAuthenticator"/> during
/// <see cref="IClientAuthenticator.CanHandle"/>. The client has not yet been resolved from the
/// repository at this point.
/// </summary>
public class TokenRequestContext
{
    /// <summary>The current HTTP context for the token endpoint request.</summary>
    public required HttpContext HttpContext { get; init; }

    /// <summary>The <c>client_id</c> value extracted from the request.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The parsed form body of the request, pre-read asynchronously by the token endpoint before
    /// any authenticator is invoked. Required as an <c>init</c> property rather than delegating
    /// to <see cref="Microsoft.AspNetCore.Http.HttpRequest.Form"/> because that getter is
    /// synchronous: it blocks when <c>AllowSynchronousIO</c> is <see langword="false"/> (the
    /// ASP.NET Core default since 3.0) and throws <see cref="System.InvalidOperationException"/>
    /// on non-form content types — both conditions are attacker-controllable.
    /// </summary>
    public required IFormCollection Form { get; init; }

    /// <summary>
    /// The HTTP request headers. Captured at context-construction time so all authenticators
    /// see a consistent snapshot. Prefer this over <c>HttpContext.Request.Headers</c> inside
    /// <see cref="IClientAuthenticator"/> implementations.
    /// </summary>
    public required IHeaderDictionary Headers { get; init; }
}
