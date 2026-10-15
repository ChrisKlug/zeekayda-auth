using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Resolves the client repository at startup, so the in-memory store's validation and hashing run before
/// any request, and checks in-memory registrations against the scopes.
/// </summary>
internal sealed class ClientRepositoryActivator(
    IServiceProvider services,
    ValidatedScopeCatalog scopeCatalog,
    SigningKeyRing? ring = null,
    InMemoryClientRegistrationOptions? inMemoryOptions = null) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ClientRepositoryActivation";

    /// <inheritdoc/>
    public async Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        // Registrations are validated against the ring's algorithm, so ask for it rather than rely on
        // activator order; EnsureInitializedAsync is idempotent.
        if (ring is not null)
            await ring.EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        // Resolved only now: building it validates every registration against that algorithm.
        var repository = services.GetRequiredService<IClientRepository>();

        if (inMemoryOptions is not null && repository is not InMemoryClientRepository)
        {
            context.AddWarning(
                "clients.inmemory_shadowed",
                "AddInMemoryClients was called but the resolved IClientRepository is " +
                "{RepositoryType}, not InMemoryClientRepository. The configured in-memory clients " +
                "are unreachable. Register a custom IClientRepository before calling " +
                "AddInMemoryClients, or remove AddInMemoryClients entirely.",
                repository.GetType().FullName);
        }

        if (repository is InMemoryClientRepository inMemory)
            await CheckAgainstScopesAsync(context, inMemory, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The authorize endpoint's per-request scope rules, applied once to the in-memory registrations. A broken
    /// scope repository is reported here too, since this read may differ from another activator's, and the
    /// client rules are then skipped rather than bury it.
    /// </summary>
    private async ValueTask CheckAgainstScopesAsync(
        StartupVerificationContext context,
        InMemoryClientRepository repository,
        CancellationToken cancellationToken)
    {
        IReadOnlyCollection<ScopeDefinition> scopes;
        try
        {
            scopes = await scopeCatalog.GetScopesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ScopeContractException ex)
        {
            foreach (var failure in ex.AggregatedFailures)
                context.AddFailure(failure.Code, failure.Message);

            return;
        }

        var defined = scopes.Select(scope => scope.Name).ToHashSet(StringComparer.Ordinal);

        foreach (var client in repository.Registrations)
        {
            foreach (var scope in client.AllowedScopes.Where(scope => !defined.Contains(scope)))
            {
                context.AddFailure(
                    "client.allowed_scopes.undefined",
                    $"Client '{client.ClientId}' allows the scope '{scope}', which IScopeRepository does not define. " +
                    "An undefined scope has no audience and unlocks no claims; define it with AddInMemoryScopes, " +
                    "or remove it from the client.");
            }

            if (ClientClaimAdditions.FindCollision(client, scopes) is { } collision)
                context.AddFailure("client.claim_additions.scope_claim", collision.Describe(client.ClientId));
        }
    }
}
