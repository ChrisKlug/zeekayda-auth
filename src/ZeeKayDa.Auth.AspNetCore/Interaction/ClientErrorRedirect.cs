using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The phase-2 error channel: an authorization error delivered to the client at the redirect URI
/// that was authenticated in phase 1. Used by the authorization endpoint's own refusals and by
/// the interaction services when a host page ends a request.
/// </summary>
/// <remarks>
/// The destination always comes from validated state — a matched registration, or the decrypted
/// interaction context — and never from request input. That is what keeps this from being an
/// unauthenticated redirect primitive.
/// </remarks>
internal sealed class ClientErrorRedirect
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public ClientErrorRedirect(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
    }

    /// <summary>
    /// Builds the redirect carrying <paramref name="error"/> and <paramref name="description"/> to
    /// <paramref name="redirectUri"/>, echoing <paramref name="state"/> when the client sent one.
    /// </summary>
    public IResult To(string redirectUri, string error, string description, string? state)
    {
        ArgumentException.ThrowIfNullOrEmpty(redirectUri);
        ArgumentException.ThrowIfNullOrEmpty(error);
        ArgumentException.ThrowIfNullOrEmpty(description);

        var query = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["error"] = error,
            ["error_description"] = description,
        };

        if (state is not null)
            query["state"] = state;

        // iss on every authorization response, unconditionally — mix-up attack mitigation
        // (RFC 9207, RFC 9700 §4.4).
        query["iss"] = _options.Value.Issuer!;

        return Results.Redirect(QueryHelpers.AddQueryString(redirectUri, query));
    }
}
