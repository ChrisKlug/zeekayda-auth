using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at application startup that <see cref="IScopeRepository"/> exposes the <c>openid</c>
/// scope, that every scope's <see cref="ScopeDefinition.Audience"/> is a resource indicator the
/// access token can carry, and that no scope lists a protocol claim it could never deliver.
/// </summary>
/// <remarks>
/// An activator rather than a verifier: <see cref="IScopeRepository.GetScopesAsync"/> is a
/// caller-supplied extension point, and while the shipped in-memory default returns a list, a custom
/// repository may run a database query.
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
    /// Every reserved protocol name a scope's lists carry, except <c>sub</c>, which the standard
    /// <c>openid</c> scope lists for readability and which every token carries regardless.
    /// </summary>
    private static IEnumerable<string> ReservedClaimsListedBy(ScopeDefinition scope) =>
        (scope.IdTokenClaims ?? []).Concat(scope.UserInfoClaims ?? []).Concat(scope.AccessTokenClaims ?? [])
            .Where(claim => claim is not null && ReservedClaimNames.IsReserved(claim) && !string.Equals(claim, "sub", StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase);
}
