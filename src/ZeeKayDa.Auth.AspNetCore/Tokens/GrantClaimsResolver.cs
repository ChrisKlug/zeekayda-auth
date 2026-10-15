using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// Turns granted scopes into the claims one destination carries, and for tokens the access token's
/// audience. One path for tokens and userinfo, so their selection rules cannot drift apart. Every
/// failure is logged here once and answered as an outcome; no claim value reaches a log line.
/// </summary>
internal sealed class GrantClaimsResolver(ValidatedScopeCatalog scopes, SanitizingLogger<GrantClaimsResolver> logger)
{
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
            definitions = await scopes.GetScopesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ScopeContractException ex)
        {
            logger.LogError(
                "Claims for a grant to client {ClientId} could not be resolved because the scope repository broke its contract: {Detail}",
                client.ClientId,
                ex.DescribeFailures());
            return GrantClaimsOutcome.Failed.Instance;
        }

        // These rules held at authorization, so a failure here is configuration changed under a live grant.
        if (!ScopeResolution.TryResolve(definitions, scope, out var granted, out var undefined))
        {
            logger.LogError("Client {ClientId} holds a grant for the scope {Scope}, which IScopeRepository no longer defines; no claims were resolved.", client.ClientId, undefined);
            return GrantClaimsOutcome.Failed.Instance;
        }

        if (!TryResolveAudience(client, granted, destination, out var resourceAudience))
            return GrantClaimsOutcome.Failed.Instance;

        if (ClientClaimAdditions.FindCollision(client, definitions) is { } collision)
        {
            logger.LogError("Client {ClientId} could not be served claims: {Detail}", client.ClientId, collision.Describe(client.ClientId));
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
    /// The resource server the granted scopes name, for tokens only: userinfo has no audience, so two
    /// named audiences must not fail it.
    /// </summary>
    private bool TryResolveAudience(
        IClient client,
        IReadOnlyList<ScopeDefinition> granted,
        ClaimsDestination destination,
        out string? resourceAudience)
    {
        resourceAudience = null;

        if (destination is not ClaimsDestination.Tokens)
            return true;

        if (!ScopeResolution.TryResolveAudience(granted, out resourceAudience))
        {
            logger.LogError("Client {ClientId} holds a grant whose scopes name more than one resource server audience; nothing was issued.", client.ClientId);
            return false;
        }

        return true;
    }

    /// <summary>
    /// The provider's answer, or <see langword="null"/> after logging when it could not be constructed,
    /// threw, or returned nothing. Only the request's own cancellation propagates.
    /// </summary>
    private async Task<ClaimsResolutionResult?> ResolvePoolAsync(
        HttpContext context,
        IClient client,
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
            logger.LogError(ex, "The claims provider failed while resolving claims for a grant to client {ClientId}; nothing was issued.", client.ClientId);
            return null;
        }

        if (result is null)
            logger.LogError("The claims provider returned null for a grant to client {ClientId}; nothing was issued.", client.ClientId);

        return result;
    }

    private static bool IsProviderFailure(Exception ex, CancellationToken cancellationToken) =>
        ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested;

    private GrantClaimsOutcome Select(
        IClient client,
        ClaimsResolutionResult.Resolved resolved,
        ClaimSelectionPlan plan,
        string? resourceAudience,
        CancellationToken cancellationToken)
    {
        // Enumerating the provider's list runs its code, so it is caught on its own.
        ClaimRecord[] pool;
        try
        {
            pool = [.. resolved.Claims];
        }
        catch (Exception ex) when (IsProviderFailure(ex, cancellationToken))
        {
            logger.LogError(ex, "The claims provider's result for a grant to client {ClientId} could not be read; nothing was issued.", client.ClientId);
            return GrantClaimsOutcome.Failed.Instance;
        }

        try
        {
            return new GrantClaimsOutcome.Issue(ClaimSelection.Select(pool, plan), resourceAudience);
        }
        catch (InvalidOperationException ex)
        {
            // Selection's own message names the claim type, never the value.
            logger.LogError("The claims provider's result for a grant to client {ClientId} could not be used: {Reason}", client.ClientId, ex.Message);
            return GrantClaimsOutcome.Failed.Instance;
        }
    }

    private GrantClaimsOutcome SubjectInvalid(IClient client)
    {
        logger.LogWarning("The claims provider reported the subject of a grant to client {ClientId} invalid; nothing was issued.", client.ClientId);
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
    IClient Client,
    string Sub,
    IReadOnlyList<string> Scope,
    string? FamilyId,
    ClaimsDestination Destination)
{
    public IClient Client { get; } = Client ?? throw new ArgumentNullException(nameof(Client));

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
