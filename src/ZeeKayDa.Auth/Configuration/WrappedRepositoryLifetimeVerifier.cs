using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Fails startup when <see cref="IScopeRepository"/> or <see cref="IClientRepository"/> is not a
/// singleton: their singleton wrappers would capture it, and ASP.NET Core catches that only in Development.
/// </summary>
internal sealed class WrappedRepositoryLifetimeVerifier(ServiceLifetimeScanner scanner) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "WrappedRepositoryLifetime";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        Check<IScopeRepository>(context, "scopes.repository.lifetime", "ValidatedScopeCatalog");
        Check<IClientRepository>(context, "clients.repository.lifetime", "ValidatedClientResolver");

        return Task.CompletedTask;
    }

    private void Check<TRepository>(StartupVerificationContext context, string code, string wrapper)
    {
        if (scanner.EffectiveLifetimeOf(typeof(TRepository)) is not { } lifetime
            || lifetime == ServiceLifetime.Singleton)
        {
            return;
        }

        context.AddFailure(
            code,
            $"{typeof(TRepository).Name} is registered as {lifetime}, but {wrapper} is a singleton and " +
            $"holds the instance it is given. A {lifetime.ToString().ToLowerInvariant()} repository would be " +
            "resolved once and then reused for the lifetime of the process, so anything scoped to a request " +
            "inside it — a DbContext, a database connection, a tenant — would be captured by the first " +
            $"request and shared by every later one. Register {typeof(TRepository).Name} as a singleton and " +
            "resolve per-request dependencies inside it from an injected IServiceScopeFactory.");
    }
}
