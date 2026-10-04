using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Holds the request-shape information available to an <see cref="IClientAuthenticator"/> during
/// <see cref="IClientAuthenticator.CanHandle"/>. The client has not yet been resolved from the
/// repository at this point.
/// </summary>
public class TokenRequestContext
{
    /// <summary>
    /// The current HTTP context for the token endpoint request: the request headers, and the
    /// connection's client certificate for mutual TLS (RFC 8705).
    /// </summary>
    public required HttpContext HttpContext { get; init; }

    /// <summary>The <c>client_id</c> value extracted from the request.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The parsed form body, pre-read asynchronously by the token endpoint before any
    /// authenticator is invoked. Use this instead of <see cref="Microsoft.AspNetCore.Http.HttpRequest.Form"/>,
    /// which is synchronous and can throw on non-form content types.
    /// </summary>
    public required IFormCollection Form { get; init; }
}
