using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Reads registrations from the live <see cref="IServiceCollection"/>, since a built provider cannot
/// say how a service was registered.
/// </summary>
internal sealed class ServiceLifetimeScanner(IServiceCollection services)
{
    /// <summary>
    /// The lifetime of the last unkeyed registration, the one unkeyed resolution gets, or
    /// <see langword="null"/> when there is none.
    /// </summary>
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
