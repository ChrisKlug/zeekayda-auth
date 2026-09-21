using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at application startup that the registered <see cref="IScopeRepository"/> keeps the
/// contract <see cref="IScopeRepository.GetScopesAsync"/> documents, by reading it through
/// <see cref="ValidatedScopeCatalog"/> — the same path every request takes — and reporting what
/// the catalog refuses.
/// </summary>
/// <remarks>
/// <para>
/// An activator rather than a verifier: <see cref="IScopeRepository.GetScopesAsync"/> is a
/// caller-supplied extension point, and while the shipped in-memory default returns a list, a
/// custom repository may run a database query.
/// </para>
/// <para>
/// <strong>The rules live in the catalog, not here.</strong> A host whose repository is broken
/// would otherwise learn it only on the first request that read it — as a server error from
/// whichever endpoint happened to be first. Reporting the catalog's own failures means startup
/// and runtime can never disagree about what the contract is, and the operator gets every
/// breach at once instead of one per restart.
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
        var catalog = scopedServices.GetRequiredService<ValidatedScopeCatalog>();

        try
        {
            await catalog.GetScopesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ScopeContractException ex)
        {
            // Only the catalog's own exception is translated. Anything else — a repository whose
            // query threw, or one throwing the public ZeeKayDaConfigurationException itself — is
            // not a contract breach the operator can read off a code, and the runner reports it
            // with its stack intact rather than flattened into a named failure carrying that
            // layer's raw text.
            foreach (var failure in ex.AggregatedFailures)
                context.AddFailure(failure.Code, failure.Message);
        }
    }
}
