using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// Turns a set of granted scopes into the subject claims one destination carries, and — for the
/// tokens the token endpoint issues — the audience its access token names: resolves the scopes,
/// checks the client's additions against them, asks the host's <see cref="IClaimsProvider"/> for
/// the pool, and selects from it. Every failure is logged here, once, and answered as an outcome.
/// One path for both destinations, so the selection rules cannot drift apart between the tokens a
/// grant becomes and the claims userinfo answers with.
/// </summary>
/// <remarks>
/// The provider is resolved from the request's services on every call: it is registered scoped,
/// so a per-request database context works, and it is called fresh per issuance by design. No
/// claim value reaches a log line from this type; a provider's exception is logged through the
/// sanitizing logger, which redacts its message and keeps its type and stack.
/// </remarks>
internal sealed class GrantClaimsResolver
{
    private readonly ValidatedScopeCatalog _scopes;
    private readonly ISanitizingLogger<GrantClaimsResolver> _logger;

    public GrantClaimsResolver(ValidatedScopeCatalog scopes, ISanitizingLogger<GrantClaimsResolver> logger)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(logger);

        _scopes = scopes;
        _logger = logger;
    }

    /// <summary>Resolves the subject claims a destination carries, or says why it could not.</summary>
    /// <param name="context">The request, whose services supply the provider.</param>
    /// <param name="request">The subject, the client, the granted scopes and what they are wanted for.</param>
    public async Task<GrantClaimsOutcome> ResolveAsync(HttpContext context, ClaimsRequest request)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        var (client, sub, scope, familyId, destination) = request;
        var cancellationToken = context.RequestAborted;
        IReadOnlyCollection<ScopeDefinition> definitions;
        try
        {
            definitions = await _scopes.GetScopesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ScopeContractException ex)
        {
            // The scope repository broke its contract after startup passed. Nothing can be
            // resolved without it, and a grant must not be served against half a configuration:
            // answered as the server error it is, with the broken rule named for the operator.
            // The codes and messages, not ex.Message: the composed message adds a count and a
            // preamble the operator does not need. Safe to log only because ScopeContractException
            // is internal, so every failure here is this framework's own text; one the repository
            // threw is not caught and never reaches a log line by message.
            _logger.LogError(
                "Claims for a grant to client {ClientId} could not be resolved because the scope repository broke its contract: {Detail}",
                client.ClientId,
                string.Join("; ", ex.AggregatedFailures.Select(failure => $"[{failure.Code}] {failure.Message}")));
            return GrantClaimsOutcome.Failed.Instance;
        }

        // Every rule below was already applied to the effective scope at the authorization
        // endpoint, and consent and refresh only narrow, so a failure here is a configuration
        // that changed under a live grant: the server's fault, and answered as such.
        if (!ScopeResolution.TryResolve(definitions, scope, out var granted, out var undefined))
        {
            _logger.LogError("Client {ClientId} holds a grant for the scope {Scope}, which IScopeRepository no longer defines; no claims were resolved.", client.ClientId, undefined);
            return GrantClaimsOutcome.Failed.Instance;
        }

        if (!TryResolveAudience(client, granted, destination, out var resourceAudience))
            return GrantClaimsOutcome.Failed.Instance;

        if (ClientClaimAdditions.FindCollision(client, definitions) is { } collision)
        {
            _logger.LogError("Client {ClientId} could not be served claims: {Detail}", client.ClientId, collision.Describe(client.ClientId));
            return GrantClaimsOutcome.Failed.Instance;
        }

        var plan = ClaimSelectionPlan.For(granted, client).For(destination);
        var result = await ResolvePoolAsync(context, client, new ClaimsProviderContext(sub, scope, plan.All, familyId), cancellationToken).ConfigureAwait(false);

        return result switch
        {
            ClaimsResolutionResult.Resolved resolved => Select(client, resolved, plan, resourceAudience, cancellationToken),
            ClaimsResolutionResult.SubjectInvalid => SubjectInvalid(client),
            _ => GrantClaimsOutcome.Failed.Instance,
        };
    }

    /// <summary>
    /// The resource server the granted scopes name, for a destination that carries one. Userinfo
    /// does not: its response has no audience, so a scope set that names two, or one whose audience
    /// is malformed, must not turn a request it has no bearing on into a server error.
    /// </summary>
    private bool TryResolveAudience(
        IClientMetadata client,
        IReadOnlyList<ScopeDefinition> granted,
        ClaimsDestination destination,
        out string? resourceAudience)
    {
        resourceAudience = null;

        if (destination is not ClaimsDestination.Tokens)
            return true;

        if (!ScopeResolution.TryResolveAudience(granted, out resourceAudience))
        {
            _logger.LogError("Client {ClientId} holds a grant whose scopes name more than one resource server audience; nothing was issued.", client.ClientId);
            return false;
        }

        return true;
    }

    /// <summary>
    /// The provider's answer, or <see langword="null"/> after logging when it could not be
    /// constructed, threw, or returned nothing. Constructing it is inside the boundary too: a
    /// provider is caller-supplied code from its constructor onwards. Only the request's own
    /// cancellation propagates; a cancellation the provider raised itself, a timeout inside it,
    /// is its failure and is answered as one.
    /// </summary>
    private async Task<ClaimsResolutionResult?> ResolvePoolAsync(
        HttpContext context,
        IClientMetadata client,
        ClaimsProviderContext providerContext,
        CancellationToken cancellationToken)
    {
        ClaimsResolutionResult? result;
        try
        {
            var provider = context.RequestServices.GetRequiredService<IClaimsProvider>();
            result = await provider.GetClaimsAsync(providerContext, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsProviderFailure(ex, cancellationToken))
        {
            _logger.LogError(ex, "The claims provider failed while resolving claims for a grant to client {ClientId}; nothing was issued.", client.ClientId);
            return null;
        }

        if (result is null)
            _logger.LogError("The claims provider returned null for a grant to client {ClientId}; nothing was issued.", client.ClientId);

        return result;
    }

    private static bool IsProviderFailure(Exception ex, CancellationToken cancellationToken) =>
        ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested;

    private GrantClaimsOutcome Select(
        IClientMetadata client,
        ClaimsResolutionResult.Resolved resolved,
        ClaimSelectionPlan plan,
        string? resourceAudience,
        CancellationToken cancellationToken)
    {
        // Materialised first, on its own: the list is the provider's, so enumerating it runs its
        // code, and anything that throws there, its own cancellation included, is logged
        // redacted, never by its message.
        ClaimRecord[] pool;
        try
        {
            pool = [.. resolved.Claims];
        }
        catch (Exception ex) when (IsProviderFailure(ex, cancellationToken))
        {
            _logger.LogError(ex, "The claims provider's result for a grant to client {ClientId} could not be read; nothing was issued.", client.ClientId);
            return GrantClaimsOutcome.Failed.Instance;
        }

        try
        {
            return new GrantClaimsOutcome.Issue(ClaimSelection.Select(pool, plan), resourceAudience);
        }
        catch (InvalidOperationException ex)
        {
            // Selection's own failure over an array it owns: the message names the claim type
            // and never the value, so it is safe to surface to the operator.
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

/// <summary>
/// One claims resolution's inputs: whose claims, for which client, under which granted scopes, and
/// what for.
/// </summary>
/// <param name="Client">The client the claims are for.</param>
/// <param name="Sub">The subject the grant was issued to.</param>
/// <param name="Scope">The granted scopes, from the stored grant or the presented token.</param>
/// <param name="FamilyId">
/// The refresh-token family of the grant, or <see langword="null"/> at userinfo, where a token
/// proves a grant existed but there is no grant in hand.
/// </param>
/// <param name="Destination">Which claims are wanted, and whether an audience must be derived.</param>
/// <exception cref="ArgumentException">Thrown when <paramref name="Sub"/> is null or empty.</exception>
/// <exception cref="ArgumentNullException">Thrown when <paramref name="Client"/> or <paramref name="Scope"/> is null.</exception>
internal sealed record ClaimsRequest(
    IClientMetadata Client,
    string Sub,
    IReadOnlyList<string> Scope,
    string? FamilyId,
    ClaimsDestination Destination)
{
    public IClientMetadata Client { get; } = Client ?? throw new ArgumentNullException(nameof(Client));

    public string Sub { get; } = !string.IsNullOrEmpty(Sub)
        ? Sub
        : throw new ArgumentException("The subject identifier must not be null or empty.", nameof(Sub));

    public IReadOnlyList<string> Scope { get; } = Scope ?? throw new ArgumentNullException(nameof(Scope));
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
