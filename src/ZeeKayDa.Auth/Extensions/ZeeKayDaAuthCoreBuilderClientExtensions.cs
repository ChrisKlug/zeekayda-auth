using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering client repositories with <see cref="ZeeKayDaAuthCoreBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthCoreBuilderClientExtensions
{
    /// <summary>
    /// Registers an in-memory client repository populated by the given <paramref name="configure"/> callback.
    /// </summary>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">A callback that registers clients on an <see cref="InMemoryClientRegistrationBuilder"/>.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Repeated calls accumulate clients. The repository is built and validated at startup, so a
    /// misconfigured client fails startup rather than the first request.
    /// </remarks>
    public static TBuilder AddInMemoryClients<TBuilder>(
        this TBuilder builder,
        Action<InMemoryClientRegistrationBuilder> configure)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // A custom IClientRepository registered before this call would silently win the
        // TryAddSingleton below, leaving the configured clients unreachable.
        var existing = builder.Services.FirstOrDefault(sd =>
            sd.ServiceType == typeof(IClientRepository) &&
            !ReferenceEquals(sd.ImplementationFactory, InMemoryClientRepository.Factory));
        if (existing is not null)
        {
            throw new InvalidOperationException(
                $"AddInMemoryClients was called after a custom IClientRepository " +
                $"({existing.ImplementationType?.Name ?? "unknown"}) was already registered. " +
                "Call AddInMemoryClients before registering a custom repository, or populate " +
                "the custom repository directly rather than using AddInMemoryClients.");
        }

        var registration = new InMemoryClientRegistrationBuilder(SharedRegistrationOptions(builder.Services));
        configure(registration);

        builder.Services.TryAddSingleton(InMemoryClientRepository.Factory);

        return builder;
    }

    private static InMemoryClientRegistrationOptions SharedRegistrationOptions(IServiceCollection services)
    {
        if (services.FirstOrDefault(sd => sd.ServiceType == typeof(InMemoryClientRegistrationOptions))
                ?.ImplementationInstance is InMemoryClientRegistrationOptions existing)
        {
            return existing;
        }

        var created = new InMemoryClientRegistrationOptions();
        services.AddSingleton(created);
        return created;
    }
}
