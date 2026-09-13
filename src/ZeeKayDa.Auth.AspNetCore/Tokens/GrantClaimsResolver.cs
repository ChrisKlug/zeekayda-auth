using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// Turns a grant into the subject claims its tokens carry and the audience its access token
/// names: resolves the granted scopes, derives the audience, checks the client's additions
/// against the scopes, asks the host's <see cref="IClaimsProvider"/> for the pool, and selects
/// from it. Every failure is logged here, once, and answered to the caller as an outcome.
/// </summary>
/// <remarks>
/// The provider is resolved from the request's services on every call: it is registered scoped,
/// so a per-request database context works, and it is called fresh per issuance by design. No
/// claim value reaches a log line from this type; a provider's exception is logged through the
/// sanitizing logger, which redacts its message and keeps its type and stack.
/// </remarks>
internal sealed class GrantClaimsResolver
{
    private readonly IScopeRepository _scopes;
    private readonly ISanitizingLogger<GrantClaimsResolver> _logger;

    public GrantClaimsResolver(IScopeRepository scopes, ISanitizingLogger<GrantClaimsResolver> logger)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(logger);

        _scopes = scopes;
        _logger = logger;
    }

    /// <param name="context">The request, whose services supply the provider.</param>
    /// <param name="client">The client the tokens are for.</param>
    /// <param name="sub">The subject the grant was issued to.</param>
    /// <param name="scope">The granted scopes, from the stored grant.</param>
    /// <param name="familyId">The refresh-token family of the grant.</param>
    public async Task<GrantClaimsOutcome> ResolveAsync(
        HttpContext context,
        IClientMetadata client,
        string sub,
        IReadOnlyList<string> scope,
        string familyId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(sub);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(familyId);

        var cancellationToken = context.RequestAborted;
        var definitions = await _scopes.GetScopesAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The registered IScopeRepository returned null from GetScopesAsync.");

        // Every rule below was already applied to the effective scope at the authorization
        // endpoint, and consent and refresh only narrow, so a failure here is a configuration
        // that changed under a live grant: the server's fault, and answered as such.
        if (!ScopeResolution.TryResolve(definitions, scope, out var granted, out var undefined))
        {
            _logger.LogError("Client {ClientId} holds a grant for the scope {Scope}, which IScopeRepository no longer defines; nothing was issued.", client.ClientId, undefined);
            return GrantClaimsOutcome.Failed.Instance;
        }

        if (!ScopeResolution.TryResolveAudience(granted, out var resourceAudience))
        {
            _logger.LogError("Client {ClientId} holds a grant whose scopes name more than one resource server audience; nothing was issued.", client.ClientId);
            return GrantClaimsOutcome.Failed.Instance;
        }

        if (ClientClaimAdditions.FindCollision(client, definitions) is { } collision)
        {
            _logger.LogError("Client {ClientId} could not be issued tokens: {Detail}", client.ClientId, collision.Describe(client.ClientId));
            return GrantClaimsOutcome.Failed.Instance;
        }

        var plan = ClaimSelectionPlan.For(granted, client);
        var result = await ResolvePoolAsync(context, client, new ClaimsProviderContext(sub, scope, plan.All, familyId), cancellationToken).ConfigureAwait(false);

        return result switch
        {
            ClaimsResolutionResult.Resolved resolved => Select(client, resolved, plan, resourceAudience),
            ClaimsResolutionResult.SubjectInvalid => SubjectInvalid(client),
            _ => GrantClaimsOutcome.Failed.Instance,
        };
    }

    /// <summary>
    /// The provider's answer, or <see langword="null"/> after logging when it threw or returned
    /// nothing. A cancellation is the client's, not the provider's, and propagates.
    /// </summary>
    private async Task<ClaimsResolutionResult?> ResolvePoolAsync(
        HttpContext context,
        IClientMetadata client,
        ClaimsProviderContext providerContext,
        CancellationToken cancellationToken)
    {
        var provider = context.RequestServices.GetRequiredService<IClaimsProvider>();

        ClaimsResolutionResult? result;
        try
        {
            result = await provider.GetClaimsAsync(providerContext, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "The claims provider failed while resolving claims for a grant to client {ClientId}; nothing was issued.", client.ClientId);
            return null;
        }

        if (result is null)
            _logger.LogError("The claims provider returned null for a grant to client {ClientId}; nothing was issued.", client.ClientId);

        return result;
    }

    private GrantClaimsOutcome Select(IClientMetadata client, ClaimsResolutionResult.Resolved resolved, ClaimSelectionPlan plan, string? resourceAudience)
    {
        try
        {
            return new GrantClaimsOutcome.Issue(ClaimSelection.Select(resolved.Claims, plan), resourceAudience);
        }
        catch (InvalidOperationException ex)
        {
            // Selection names the claim type in its message and never the value, so the message
            // is safe to surface to the operator, who owns the provider that produced it.
            _logger.LogError("The claims provider's result for a grant to client {ClientId} could not be used: {Reason}", client.ClientId, ex.Message);
            return GrantClaimsOutcome.Failed.Instance;
        }
    }

    private GrantClaimsOutcome SubjectInvalid(IClientMetadata client)
    {
        _logger.LogWarning("The claims provider reported the subject of a grant to client {ClientId} invalid; nothing was issued.", client.ClientId);
        return GrantClaimsOutcome.SubjectInvalid.Instance;
    }
}

/// <summary>What resolving a grant's claims came to. Closed: a caller handles exactly these three.</summary>
internal abstract record GrantClaimsOutcome
{
    private GrantClaimsOutcome()
    {
    }

    /// <summary>The claims each token carries, and the resource server the access token names, if any.</summary>
    public sealed record Issue(SelectedClaims Claims, string? ResourceAudience) : GrantClaimsOutcome;

    /// <summary>The subject must not receive tokens: <c>invalid_grant</c>.</summary>
    public sealed record SubjectInvalid : GrantClaimsOutcome
    {
        public static SubjectInvalid Instance { get; } = new();
    }

    /// <summary>An infrastructure or configuration failure, already logged: <c>server_error</c>.</summary>
    public sealed record Failed : GrantClaimsOutcome
    {
        public static Failed Instance { get; } = new();
    }
}
