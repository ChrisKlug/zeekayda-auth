using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Reads the scope repository through <see cref="ValidatedScopeCatalog"/> at startup, as every request does,
/// and reports every breach at once. An activator because a custom repository may query a database.
/// </summary>
internal sealed class ScopePresenceActivator(ValidatedScopeCatalog catalog) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ScopePresence";

    /// <inheritdoc/>
    public async Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        try
        {
            await catalog.GetScopesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ScopeContractException ex)
        {
            // Only the catalog's own: anything a repository threw keeps its stack and never has its text logged.
            foreach (var failure in ex.AggregatedFailures)
                context.AddFailure(failure.Code, failure.Message);
        }
    }
}
