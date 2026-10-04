using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Authenticates clients using <c>client_secret_basic</c> (HTTP Basic authentication) or
/// <c>client_secret_post</c> (client secret in the request body).
/// </summary>
/// <remarks>
/// Uses only the public contract a third-party authenticator has: a malformed request is refused with
/// <see cref="ClientAuthenticationResult.NotValid"/>, and a presented secret is checked by
/// <see cref="ClientSecrets.Verify"/>, never compared directly.
/// </remarks>
internal sealed class ClientSecretAuthenticator(ClientSecrets secrets) : IClientAuthenticator
{
    private static readonly IReadOnlySet<string> _authMethods =
        new HashSet<string>(StringComparer.Ordinal)
        {
            TokenEndpointAuthMethods.ClientSecretBasic,
            TokenEndpointAuthMethods.ClientSecretPost,
        };

    /// <inheritdoc/>
    public IReadOnlySet<string> AuthenticationMethods => _authMethods;

    /// <inheritdoc/>
    /// <remarks>
    /// Returns <see langword="true"/> with <c>client_secret_basic</c> when an
    /// <c>Authorization: Basic</c> header is present — including the case where a
    /// simultaneous <c>client_secret</c> form field is present, which
    /// <see cref="AuthenticateAsync"/> rejects. Returns <see langword="true"/> with
    /// <c>client_secret_post</c> when only a <c>client_secret</c> form field is present.
    /// Returns <see langword="false"/> when neither is present.
    /// </remarks>
    public bool CanHandle(TokenRequestContext context, out string? method)
    {
        ArgumentNullException.ThrowIfNull(context);

        var hasBasic = BasicAuthorizationHeader.IsPresent(context.Headers);
        var hasPost = context.Form.ContainsKey("client_secret");

        if (hasBasic)
        {
            method = TokenEndpointAuthMethods.ClientSecretBasic;
            return true;
        }

        if (hasPost)
        {
            method = TokenEndpointAuthMethods.ClientSecretPost;
            return true;
        }

        method = null;
        return false;
    }

    /// <inheritdoc/>
    public Task<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        return Task.FromResult(PresentedSecret(context) is { } presented
            ? ClientAuthenticationResult.From(secrets.Verify(presented, context.Client.Secrets))
            : ClientAuthenticationResult.NotValid());
    }

    /// <summary>The secret the request presents, or <see langword="null"/> when the request is malformed.</summary>
    private static string? PresentedSecret(ClientAuthenticationContext context)
    {
        var hasBasic = BasicAuthorizationHeader.IsPresent(context.Headers);
        var hasPost = context.Form.ContainsKey("client_secret");

        // RFC 6749 §2.3: a client MUST NOT use more than one authentication method per request.
        if (hasBasic && hasPost)
            return null;

        if (!hasBasic)
            return context.Form["client_secret"].ToString();

        // RFC 6749 §2.3.1: the Basic-auth username is the authoritative client_id.
        if (!BasicAuthorizationHeader.TryParse(context.Headers, out var username, out var password) ||
            !string.Equals(username, context.ClientId, StringComparison.Ordinal))
            return null;

        // Two conflicting client_id values in one request is a protocol error, whichever one the
        // caller used to look up the client.
        var formClientId = context.Form["client_id"].ToString();
        return formClientId.Length > 0 && !string.Equals(formClientId, username, StringComparison.Ordinal)
            ? null
            : password;
    }
}
