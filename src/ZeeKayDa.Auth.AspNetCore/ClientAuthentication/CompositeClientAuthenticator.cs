using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Coordinates all registered <see cref="IClientAuthenticator"/> implementations for token
/// endpoint client authentication, implementing the documented dispatch rules.
/// </summary>
/// <remarks>
/// Registered as the concrete type — not as <see cref="IClientAuthenticator"/> — so it is
/// excluded from the injected authenticator enumerable and cannot be dispatched recursively.
/// </remarks>
internal sealed class CompositeClientAuthenticator(
    IEnumerable<IClientAuthenticator> authenticators,
    ValidatedClientResolver clientResolver,
    IOptions<AuthorizationServerOptions> serverOptions,
    ClientSecrets secrets,
    SanitizingLogger<CompositeClientAuthenticator> logger)
{
    private readonly IReadOnlyList<IClientAuthenticator> _authenticators = authenticators.ToList().AsReadOnly();

    /// <summary>
    /// Authenticates the client identified by <paramref name="clientId"/> using the mechanism(s)
    /// detected in the current request.
    /// </summary>
    /// <param name="clientId">The <c>client_id</c> extracted from the token request.</param>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="cancellationToken">Propagates notification that the operation should be cancelled.</param>
    public async ValueTask<AuthenticatedClient> AuthenticateAsync(
        string clientId,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(httpContext);

        // HttpRequest.Form is synchronous and throws on non-form content types, both of which are
        // attacker-controllable, so read it asynchronously up front.
        var form = httpContext.Request.HasFormContentType
            ? await httpContext.Request.ReadFormAsync(cancellationToken)
            : FormCollection.Empty;
        var headers = httpContext.Request.Headers;

        // RFC 7235 §4.2: a request MUST NOT carry more than one Authorization header field.
        // Reject before CanHandle so no authenticator ever sees an ambiguous header set.
        if (headers.Authorization.Count > 1)
            return AuthenticatedClient.Refused;

        // CanHandle is a shape check; built without the client so the repository isn't consulted
        // for requests rejected early. Authenticators MUST NOT access context.Client here.
        var canHandleContext = new TokenRequestContext
        {
            HttpContext = httpContext,
            ClientId = clientId,
            Form = form,
            Headers = headers,
        };

        var matches = _authenticators
            .Select(authenticator =>
            {
                var canHandle = TryCanHandle(authenticator, canHandleContext, out var method);
                return new { authenticator, canHandle, method };
            })
            .Where(x => x.canHandle)
            .Select(x => (Authenticator: x.authenticator, Method: x.method!))
            .ToList();

        // Multiple mechanisms → invalid_client (RFC 6749 §2.3).
        if (matches.Count > 1)
            return AuthenticatedClient.Refused;

        // Repository lookup deferred past the early-reject check above so ambiguous or
        // conflicting requests never incur unnecessary I/O.
        var client = await clientResolver.FindClientWithCredentialsAsync(clientId, cancellationToken);

        // No mechanism → none fallback.
        if (matches.Count == 0)
            return AuthenticateNone(client);

        // Exactly one mechanism.
        var (matchedAuthenticator, matchedMethod) = matches[0];

        // Returned method must be in the authenticator's own declared set (defends against a
        // buggy CanHandle that returns an undeclared method, bypassing the coverage check).
        if (!matchedAuthenticator.AuthenticationMethods.ContainsOrdinal(matchedMethod))
            return AuthenticatedClient.Refused;

        // Method must be in the server's global allowlist.
        if (!IsMethodAllowedByServer(matchedMethod))
            return AuthenticatedClient.Refused;

        // Unknown client, or one that does not allow this method (ordinal): indistinguishable.
        if (client is null || !client.AllowedTokenEndpointAuthMethods.ContainsOrdinal(matchedMethod))
            return RefuseAfterPadding();

        // Delegate to the authenticator. Client is guaranteed non-null here.
        var context = new ClientAuthenticationContext
        {
            HttpContext = httpContext,
            ClientId = clientId,
            Client = client,
            Form = form,
            Headers = headers,
        };
        // A null from a caller-supplied authenticator is a refusal, not a fault to surface.
        return await matchedAuthenticator.AuthenticateAsync(context, cancellationToken) switch
        {
            { Authenticated: true } => AuthenticatedClient.Accepted(client),
            { FailurePadded: true } => AuthenticatedClient.Refused,
            _ => RefuseAfterPadding(),
        };
    }

    private bool TryCanHandle(IClientAuthenticator authenticator, TokenRequestContext context, out string? method)
    {
        try
        {
            return authenticator.CanHandle(context, out method);
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "Authenticator {AuthenticatorType} threw from CanHandle; treating as non-matching.",
                authenticator.GetType().FullName);
            method = null;
            return false;
        }
    }

    private AuthenticatedClient AuthenticateNone(IClientWithCredentials? client)
    {
        // A public client has no credentials and allows exactly { "none" }: the resolver serves only
        // registrations that passed the validator, which enforces that three-way rule.
        if (!IsMethodAllowedByServer(TokenEndpointAuthMethods.None) || client is not { IsPublic: true })
            return RefuseAfterPadding();

        // Success intentionally skips padding: it's already visible in the HTTP response, and
        // client_id is not a secret in OAuth.
        return AuthenticatedClient.Accepted(client);
    }

    /// <summary>
    /// A refusal that checked no secret, padded to the cost of a wrong one so its timing does not
    /// reveal whether the client exists or how it may authenticate.
    /// </summary>
    private AuthenticatedClient RefuseAfterPadding()
    {
        secrets.Verify(presented: [], stored: []);
        return AuthenticatedClient.Refused;
    }

    private bool IsMethodAllowedByServer(string method)
        => serverOptions.Value.TokenEndpoint.AuthMethodsSupported
            .Contains(method, StringComparer.Ordinal);
}
