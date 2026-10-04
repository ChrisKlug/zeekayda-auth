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
/// <see cref="IClientSecrets.Verify"/>, never compared directly.
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
    /// An <c>Authorization: Basic</c> header is <c>client_secret_basic</c> and a <c>client_secret</c>
    /// form field is <c>client_secret_post</c>. Both at once is refused: RFC 6749 §2.3 allows one
    /// authentication method per request.
    /// </remarks>
    public ClientAuthenticatorMatch CanHandle(TokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var hasBasic = BasicAuthorizationHeader.IsPresent(context.HttpContext.Request.Headers);
        var hasPost = context.Form.ContainsKey("client_secret");

        return (hasBasic, hasPost) switch
        {
            (true, true) => ClientAuthenticatorMatch.Refused,
            (true, false) => ClientAuthenticatorMatch.For(TokenEndpointAuthMethods.ClientSecretBasic),
            (false, true) => ClientAuthenticatorMatch.For(TokenEndpointAuthMethods.ClientSecretPost),
            _ => ClientAuthenticatorMatch.None,
        };
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
    private static string? PresentedSecret(ClientAuthenticationContext context) =>
        context.Method == TokenEndpointAuthMethods.ClientSecretBasic
            ? BasicAuthorizationHeader.SecretFor(context.HttpContext.Request.Headers, context.ClientId, context.Form)
            : context.Form["client_secret"].ToString();
}
