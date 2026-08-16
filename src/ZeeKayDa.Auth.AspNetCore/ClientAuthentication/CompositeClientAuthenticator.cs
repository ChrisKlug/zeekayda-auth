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
internal sealed class CompositeClientAuthenticator
{
    private readonly IReadOnlyList<IClientAuthenticator> _authenticators;
    private readonly IClientRepository _clientRepository;
    private readonly IOptions<AuthorizationServerOptions> _serverOptions;
    private readonly CompositeClientSecretHasher _secretHasher;
    private readonly ISanitizingLogger<CompositeClientAuthenticator> _logger;

    public CompositeClientAuthenticator(
        IEnumerable<IClientAuthenticator> authenticators,
        IClientRepository clientRepository,
        IOptions<AuthorizationServerOptions> serverOptions,
        CompositeClientSecretHasher secretHasher,
        ISanitizingLogger<CompositeClientAuthenticator> logger)
    {
        ArgumentNullException.ThrowIfNull(authenticators);
        ArgumentNullException.ThrowIfNull(clientRepository);
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(secretHasher);
        ArgumentNullException.ThrowIfNull(logger);

        _authenticators = authenticators.ToList().AsReadOnly();
        _clientRepository = clientRepository;
        _serverOptions = serverOptions;
        _secretHasher = secretHasher;
        _logger = logger;
    }

    /// <summary>
    /// Authenticates the client identified by <paramref name="clientId"/> using the mechanism(s)
    /// detected in the current request.
    /// </summary>
    /// <param name="clientId">The <c>client_id</c> extracted from the token request.</param>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="cancellationToken">Propagates notification that the operation should be cancelled.</param>
    public async ValueTask<ClientAuthenticationResult> AuthenticateAsync(
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
            return ClientAuthenticationResult.NotValid();

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
            return ClientAuthenticationResult.NotValid();

        // Repository lookup deferred past the early-reject check above so ambiguous or
        // conflicting requests never incur unnecessary I/O.
        var client = await _clientRepository.FindByClientIdAsync(clientId, cancellationToken);

        // No mechanism → none fallback.
        if (matches.Count == 0)
            return AuthenticateNone(client);

        // Exactly one mechanism.
        var (matchedAuthenticator, matchedMethod) = matches[0];

        // Returned method must be in the authenticator's own declared set (defends against a
        // buggy CanHandle that returns an undeclared method, bypassing the coverage check).
        if (!matchedAuthenticator.AuthenticationMethods.ContainsOrdinal(matchedMethod))
            return ClientAuthenticationResult.NotValid();

        // Method must be in the server's global allowlist.
        if (!IsMethodAllowedByServer(matchedMethod))
            return ClientAuthenticationResult.NotValid();

        // Unknown client → invalid_client with timing padding.
        if (client is null)
        {
            _secretHasher.PadToCredentialBudget();
            return ClientAuthenticationResult.NotValid();
        }

        // Method must be in the per-client allowlist (ordinal). Pad timing to match the
        // unknown-client path so "client exists but wrong method" is not timing-distinguishable
        // from "client does not exist".
        if (!client.AllowedTokenEndpointAuthMethods.ContainsOrdinal(matchedMethod))
        {
            _secretHasher.PadToCredentialBudget();
            return ClientAuthenticationResult.NotValid();
        }

        // Delegate to the authenticator. Client is guaranteed non-null here.
        var context = new ClientAuthenticationContext
        {
            HttpContext = httpContext,
            ClientId = clientId,
            Client = client,
            Form = form,
            Headers = headers,
        };
        return await matchedAuthenticator.AuthenticateAsync(context, cancellationToken);
    }

    private bool TryCanHandle(IClientAuthenticator authenticator, TokenRequestContext context, out string? method)
    {
        try
        {
            return authenticator.CanHandle(context, out method);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Authenticator {AuthenticatorType} threw from CanHandle; treating as non-matching.",
                authenticator.GetType().FullName);
            method = null;
            return false;
        }
    }

    private ClientAuthenticationResult AuthenticateNone(IClientRegistration? client)
    {
        // Server must advertise "none". Routed through IsMethodAllowedByServer so there is one
        // server-allowlist code path.
        if (!IsMethodAllowedByServer(TokenEndpointAuthMethods.None))
        {
            PadNoneRejection();
            return ClientAuthenticationResult.NotValid();
        }

        // Client must exist.
        if (client is null)
        {
            PadNoneRejection();
            return ClientAuthenticationResult.NotValid();
        }

        // Client must be public.
        if (!client.IsPublic)
        {
            PadNoneRejection();
            return ClientAuthenticationResult.NotValid();
        }

        // Client must have no credentials (three-way consistency rule).
        if (client.Credentials.Count != 0)
        {
            PadNoneRejection();
            return ClientAuthenticationResult.NotValid();
        }

        // Client's AllowedTokenEndpointAuthMethods must be exactly { "none" } (ordinal).
        if (client.AllowedTokenEndpointAuthMethods.Count != 1 ||
            !client.AllowedTokenEndpointAuthMethods.ContainsOrdinal(TokenEndpointAuthMethods.None))
        {
            PadNoneRejection();
            return ClientAuthenticationResult.NotValid();
        }

        // Success intentionally skips padding: it's already visible in the HTTP response, and
        // client_id is not a secret in OAuth.
        return ClientAuthenticationResult.Valid();
    }

    private void PadNoneRejection() => _secretHasher.PadToCredentialBudget();

    private bool IsMethodAllowedByServer(string method)
        => _serverOptions.Value.TokenEndpoint.AuthMethodsSupported
            .Contains(method, StringComparer.Ordinal);

}
