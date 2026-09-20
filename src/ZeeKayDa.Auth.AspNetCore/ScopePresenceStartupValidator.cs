using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at application startup that <see cref="IScopeRepository"/> exposes the <c>openid</c>
/// scope, that every scope and claim it returns is actually named, that every scope's
/// <see cref="ScopeDefinition.Audience"/> is a resource indicator the access token can carry, and
/// that no scope lists a protocol claim it could never deliver.
/// </summary>
/// <remarks>
/// An activator rather than a verifier: <see cref="IScopeRepository.GetScopesAsync"/> is a
/// caller-supplied extension point, and while the shipped in-memory default returns a list, a custom
/// repository may run a database query.
/// </remarks>
/// <remarks>
/// <para>
/// <strong>A custom repository is checked here because nothing else checks it.</strong>
/// <c>InMemoryScopeRepository</c> refuses a null, empty or whitespace claim name in its
/// constructor, but a custom <see cref="IScopeRepository"/> never runs that constructor and
/// <see cref="ScopeDefinition"/>'s non-nullable declarations are not enforced at runtime. Consumers
/// had each been defending themselves instead — <c>ClaimSelectionPlan</c> and
/// <c>ClientClaimAdditions</c> read a null list as empty, the discovery document drops a blank
/// claim name — which keeps the process up but tells the operator nothing, and leaves a claim
/// configured that <see cref="ClaimRecord"/> guarantees no provider can ever deliver.
/// </para>
/// </remarks>
internal sealed class ScopePresenceStartupValidator : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ScopePresence";

    /// <inheritdoc/>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var repository = scopedServices.GetRequiredService<IScopeRepository>();
        var scopes = await repository.GetScopesAsync(cancellationToken);

        if (!scopes.Any(s => string.Equals(s.Name, StandardScopes.OpenId.Name, StringComparison.Ordinal)))
        {
            context.AddFailure(
                "scopes.openid_missing",
                $"IScopeRepository must include the '{StandardScopes.OpenId.Name}' scope. " +
                $"Every OpenID Connect authorization request is required to include '{StandardScopes.OpenId.Name}'.");
        }

        foreach (var scope in scopes.Where(scope => string.IsNullOrWhiteSpace(scope.Name)))
        {
            context.AddFailure(
                "scopes.name.blank",
                "IScopeRepository returned a scope with no name. A scope's name is what a client " +
                "requests and what the discovery document publishes in scopes_supported, which " +
                $"OpenID Connect Discovery 1.0 §3 defines as a list of strings. Scope: '{scope.Name}'.");
        }

        foreach (var (scope, claim) in scopes.SelectMany(scope => BlankClaimsListedBy(scope).Select(claim => (scope, claim))))
        {
            context.AddFailure(
                "scopes.claims.blank",
                $"Scope '{scope.Name}' lists a claim with no name. ClaimRecord refuses a null, empty " +
                "or whitespace claim type, so no claims provider can ever deliver it and selection " +
                "would carry it for nothing; remove it from the scope.");
        }

        foreach (var scope in scopes.Where(scope => scope.Audience is not null && !ScopeResolution.IsResourceIndicator(scope.Audience)))
        {
            context.AddFailure(
                "scopes.audience.invalid",
                $"Scope '{scope.Name}' has an Audience of '{scope.Audience}', which is not an absolute URI without a " +
                "fragment. RFC 8707 §2 requires both of a resource indicator, and the value becomes the access " +
                "token's aud claim as written.");
        }

        foreach (var (scope, claim) in scopes.SelectMany(scope => ReservedClaimsListedBy(scope).Select(claim => (scope, claim))))
        {
            context.AddFailure(
                "scopes.claims.reserved",
                $"Scope '{scope.Name}' lists '{claim}', a protocol claim the framework writes from the grant. A " +
                "claims provider cannot supply it and selection never delivers it; remove it from the scope.");
        }
    }

    /// <summary>
    /// At most one blank claim name per scope: the failure says the scope lists an unnamed claim,
    /// and repeating that per blank entry would tell the operator nothing new about the same fix.
    /// </summary>
    private static IEnumerable<string> BlankClaimsListedBy(ScopeDefinition scope) =>
        AllClaimsListedBy(scope).Where(string.IsNullOrWhiteSpace).Take(1);

    /// <summary>Every claim name a scope lists, reading a null list as no claims at all.</summary>
    private static IEnumerable<string> AllClaimsListedBy(ScopeDefinition scope) =>
        (scope.IdTokenClaims ?? []).Concat(scope.UserInfoClaims ?? []).Concat(scope.AccessTokenClaims ?? []);

    /// <summary>
    /// Every reserved protocol name a scope's lists carry, except <c>sub</c>, which the standard
    /// <c>openid</c> scope lists for readability and which every token carries regardless.
    /// </summary>
    private static IEnumerable<string> ReservedClaimsListedBy(ScopeDefinition scope) =>
        AllClaimsListedBy(scope)
            .Where(claim => claim is not null && ReservedClaimNames.IsReserved(claim) && !string.Equals(claim, "sub", StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase);
}
