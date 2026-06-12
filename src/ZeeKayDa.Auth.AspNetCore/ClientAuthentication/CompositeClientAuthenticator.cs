using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Coordinates all registered <see cref="IClientAuthenticator"/> implementations for token
/// endpoint client authentication, implementing the dispatch rules from ADR 0007 §4.
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

    public CompositeClientAuthenticator(
        IEnumerable<IClientAuthenticator> authenticators,
        IClientRepository clientRepository,
        IOptions<AuthorizationServerOptions> serverOptions,
        CompositeClientSecretHasher secretHasher)
    {
        ArgumentNullException.ThrowIfNull(authenticators);
        ArgumentNullException.ThrowIfNull(clientRepository);
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(secretHasher);

        _authenticators = authenticators.ToList().AsReadOnly();
        _clientRepository = clientRepository;
        _serverOptions = serverOptions;
        _secretHasher = secretHasher;
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

        // ADR 0007 §4 step 1: CanHandle is a shape check — build a context without the client
        // so the repository is not consulted for requests that will be rejected early.
        // Authenticators MUST NOT access context.Client inside CanHandle.
        var canHandleContext = new TokenRequestContext
        {
            HttpContext = httpContext,
            ClientId = clientId,
        };

        var matches = new List<(IClientAuthenticator Authenticator, string Method)>();
        foreach (var authenticator in _authenticators)
        {
            if (authenticator.CanHandle(canHandleContext, out var method))
                matches.Add((authenticator, method!));
        }

        // ADR 0007 §4 step 3: multiple mechanisms → invalid_client (RFC 6749 §2.3).
        if (matches.Count > 1)
            return ClientAuthenticationResult.NotValid();

        // Detect simultaneous presentation of conflicting mechanisms before hitting the
        // repository. ClientSecretAuthenticator.CanHandle returns false in this case (belt-
        // and-braces), which would otherwise let the request fall to the none fallback.
        if (matches.Count == 0 && HasConflictingMechanisms(canHandleContext))
            return ClientAuthenticationResult.NotValid();

        // Repository lookup deferred past the early-reject checks above so ambiguous or
        // conflicting requests never incur unnecessary I/O.
        var client = await _clientRepository.FindByClientIdAsync(clientId, cancellationToken);

        // ADR 0007 §4 step 4: no mechanism → none fallback.
        if (matches.Count == 0)
            return AuthenticateNone(client);

        // ADR 0007 §4 step 5: exactly one mechanism.
        var (matchedAuthenticator, matchedMethod) = matches[0];

        // Returned method must be in the authenticator's own declared set (defends against a
        // buggy CanHandle that returns an undeclared method, bypassing the coverage check).
        if (!matchedAuthenticator.AuthenticationMethods.Contains(matchedMethod, StringComparer.Ordinal))
            return ClientAuthenticationResult.NotValid();

        // Method must be in the server's global allowlist.
        if (!IsMethodAllowedByServer(matchedMethod))
            return ClientAuthenticationResult.NotValid();

        // Unknown client → invalid_client with timing padding (ADR 0007 §3.4).
        if (client is null)
        {
            for (var i = 0; i < CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient; i++)
                _secretHasher.VerifyUnknownClientForTimingOnly(string.Empty.AsSpan());
            return ClientAuthenticationResult.NotValid();
        }

        // Method must be in the per-client allowlist (ordinal). Pad timing to match the
        // unknown-client path so "client exists but wrong method" is not timing-distinguishable
        // from "client does not exist" (ADR 0007 §3.4).
        if (!client.AllowedTokenEndpointAuthMethods.Contains(matchedMethod, StringComparer.Ordinal))
        {
            for (var i = 0; i < CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient; i++)
                _secretHasher.VerifyUnknownClientForTimingOnly(string.Empty.AsSpan());
            return ClientAuthenticationResult.NotValid();
        }

        // ADR 0007 §4 step 6: delegate to the authenticator. Client is guaranteed non-null here.
        var context = new ClientAuthenticationContext
        {
            HttpContext = httpContext,
            ClientId = clientId,
            Client = client,
        };
        return await matchedAuthenticator.AuthenticateAsync(context, cancellationToken);
    }

    private ClientAuthenticationResult AuthenticateNone(IClientRegistration? client)
    {
        // Server must advertise "none". Routed through IsMethodAllowedByServer so there is one
        // server-allowlist code path, consistent with ADR 0007 §1a amendment.
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

        // Client must have no credentials (three-way consistency rule, ADR 0007 §1).
        if (client.Credentials.Count != 0)
        {
            PadNoneRejection();
            return ClientAuthenticationResult.NotValid();
        }

        // Client's AllowedTokenEndpointAuthMethods must be exactly { "none" } (ordinal).
        if (client.AllowedTokenEndpointAuthMethods.Count != 1 ||
            !client.AllowedTokenEndpointAuthMethods.Contains(
                TokenEndpointAuthMethods.None, StringComparer.Ordinal))
        {
            PadNoneRejection();
            return ClientAuthenticationResult.NotValid();
        }

        return ClientAuthenticationResult.Valid();
    }

    private void PadNoneRejection()
    {
        for (var i = 0; i < CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient; i++)
            _secretHasher.VerifyUnknownClientForTimingOnly(string.Empty.AsSpan());
    }

    private bool IsMethodAllowedByServer(string method)
    {
        // NOTE: TokenEndpointOptions.AuthMethodsSupported is currently ICollection<TokenEndpointAuthMethod>
        // (enum). This conversion layer will be removed once the follow-up issue changes it to
        // ICollection<string> (ADR 0007 §1a amendment).
        foreach (var serverMethod in _serverOptions.Value.TokenEndpoint.AuthMethodsSupported)
        {
            if (string.Equals(ToMethodString(serverMethod), method, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static string ToMethodString(TokenEndpointAuthMethod method) => method switch
    {
        TokenEndpointAuthMethod.ClientSecretBasic => TokenEndpointAuthMethods.ClientSecretBasic,
        TokenEndpointAuthMethod.ClientSecretPost => TokenEndpointAuthMethods.ClientSecretPost,
        TokenEndpointAuthMethod.None => TokenEndpointAuthMethods.None,
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, null),
    };

    private static bool HasConflictingMechanisms(TokenRequestContext context)
    {
        // Multiple Authorization headers are themselves ambiguous — reject.
        if (context.Headers.Authorization.Count > 1)
            return true;

        var hasBasic = context.Headers.Authorization.Count == 1 &&
                       context.Headers.Authorization[0] is { } value &&
                       value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase);
        var hasPost = context.Form.ContainsKey("client_secret");
        return hasBasic && hasPost;
    }
}
