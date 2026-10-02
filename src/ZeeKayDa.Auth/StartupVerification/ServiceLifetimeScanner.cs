using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Reports the lifetime a service type was registered under, by reading the
/// <see cref="IServiceCollection"/> itself.
/// </summary>
/// <remarks>
/// The constructor captures the collection reference, so the lifetime reported is the one in force
/// when it is asked, not the one at registration: a built <see cref="IServiceProvider"/> can say
/// whether a service exists but not how it was registered.
/// </remarks>
internal sealed class ServiceLifetimeScanner(IServiceCollection services)
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

    /// <summary>Every unkeyed registration of <paramref name="serviceType"/>, in registration order.</summary>
    public IEnumerable<ServiceDescriptor> RegistrationsOf(Type serviceType) =>
        services.Where(descriptor => !descriptor.IsKeyedService && descriptor.ServiceType == serviceType);

    /// <summary>Every registration of <paramref name="serviceType"/>, keyed ones included.</summary>
    public IEnumerable<ServiceDescriptor> AllRegistrationsOf(Type serviceType) =>
        services.Where(descriptor => descriptor.ServiceType == serviceType);
}
