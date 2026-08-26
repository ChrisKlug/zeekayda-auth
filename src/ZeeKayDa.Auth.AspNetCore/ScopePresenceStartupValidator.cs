using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies that <see cref="IScopeRepository"/> exposes the <c>openid</c> scope at application startup.
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
    }
}
