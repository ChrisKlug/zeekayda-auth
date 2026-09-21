using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at application startup that <see cref="IScopeRepository"/> and
/// <see cref="IClientRepository"/> are registered as singletons, because the framework types that
/// wrap them — <c>ValidatedScopeCatalog</c> and <c>ValidatedClientResolver</c> — are singletons
/// and hold the instance they were given.
/// </summary>
/// <remarks>
/// <para>
/// <strong>A captive dependency, caught at startup instead of in production.</strong> A repository
/// registered as scoped or transient is resolved once, when the wrapper is first constructed, and
/// that one instance is then used for the lifetime of the process. For the shape the framework's
/// own documentation invites — a repository running a database query — that means an
/// <c>EF Core</c> <c>DbContext</c>, or the connection under it, held open forever and shared by
/// every concurrent request, which is neither thread-safe nor what the host asked for.
/// </para>
/// <para>
/// ASP.NET Core's own scope validation catches this only in Development, where
/// <c>WebApplicationBuilder</c> turns it on by default. In Production it is silent, so the
/// deployment that surfaces the bug is the one nobody is watching. Failing startup makes the two
/// environments agree.
/// </para>
/// <para>
/// The <see cref="IServiceCollection"/> is read rather than the built provider, because a
/// provider can report that a service exists but not the lifetime it was registered under. The
/// scanner captures the collection at registration, the same way
/// <c>SanitizingLoggerClosedOverrideScanner</c> does, so this sees every registration a host added
/// — including ones added after <c>AddZeeKayDaAuth</c>.
/// </para>
/// </remarks>
internal sealed class WrappedRepositoryLifetimeValidator(RepositoryLifetimeScanner scanner) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "WrappedRepositoryLifetime";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        Check<IScopeRepository>(context, "scopes.repository.lifetime", "ValidatedScopeCatalog");
        Check<IClientRepository>(context, "clients.repository.lifetime", "ValidatedClientResolver");

        return ValueTask.CompletedTask;
    }

    private void Check<TRepository>(StartupVerificationContext context, string code, string wrapper)
    {
        // A repository registered several times resolves to the last registration, so that is the
        // one whose lifetime decides what the wrapper captures.
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

/// <summary>
/// Reports the lifetime a service type was registered under, by reading the
/// <see cref="IServiceCollection"/> itself.
/// </summary>
/// <remarks>
/// The constructor captures the collection reference, so the lifetime reported is the one in force
/// when it is asked, not the one at registration. See <c>SanitizingLoggerClosedOverrideScanner</c>,
/// which reads the same collection the same way and for the same reason: a built
/// <see cref="IServiceProvider"/> can say whether a service exists but not how it was registered.
/// </remarks>
internal sealed class RepositoryLifetimeScanner(IServiceCollection services)
{
    /// <summary>
    /// The lifetime of the registration that would win resolution for <paramref name="serviceType"/>
    /// — the last unkeyed one added — or <see langword="null"/> when it is not registered at all,
    /// which is a different check's failure to report.
    /// </summary>
    /// <remarks>
    /// Keyed registrations are skipped, and skipping them is the point rather than tidiness. The
    /// wrappers resolve <paramref name="serviceType"/> unkeyed, so a keyed registration is never
    /// what they capture; counting one would let a host that registers an unkeyed scoped
    /// repository and then a keyed singleton for some unrelated purpose pass this check while the
    /// scoped instance is the one actually held.
    /// </remarks>
    public ServiceLifetime? EffectiveLifetimeOf(Type serviceType) =>
        services
            .LastOrDefault(descriptor => !descriptor.IsKeyedService && descriptor.ServiceType == serviceType)
            ?.Lifetime;
}
