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

    /// <summary>The parsed form body of the request.</summary>
    public IFormCollection Form => HttpContext.Request.Form;

    /// <summary>The HTTP request headers.</summary>
    public IHeaderDictionary Headers => HttpContext.Request.Headers;
}
