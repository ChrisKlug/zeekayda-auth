using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth;

/// <summary>
/// A builder for configuring ZeeKayDa.Auth services.
/// </summary>
/// <remarks>
/// Returned by <c>AddZeeKayDaAuth()</c>. Use extension methods on this builder to register
/// optional features (signing keys, client stores, etc.) without adding properties to
/// <see cref="AuthorizationServerOptions"/>.
/// </remarks>
public sealed class ZeeKayDaAuthBuilder
{
    /// <summary>
    /// Initialises a new <see cref="ZeeKayDaAuthBuilder"/> instance.
    /// </summary>
    /// <remarks>
    /// This constructor is intended for use in provider package tests. Application code should
    /// obtain a builder via <c>AddZeeKayDaAuth()</c>.
    /// </remarks>
    /// <param name="services">The application service collection.</param>
    public ZeeKayDaAuthBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> if <paramref name="serviceType"/> is
    /// already registered in <see cref="Services"/>.
    /// </summary>
    /// <remarks>
    /// This method is intended for provider package authors implementing
    /// <see cref="ZeeKayDaAuthBuilder"/> extension methods. Application code should not call
    /// it directly.
    /// </remarks>
    /// <param name="serviceType">The service interface type to check for duplicate registration.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="serviceType"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a <see cref="ServiceDescriptor"/> with
    /// <see cref="ServiceDescriptor.ServiceType"/> equal to <paramref name="serviceType"/>
    /// already exists in <see cref="Services"/>.
    /// </exception>
    public void ThrowIfAlreadyRegistered(Type serviceType)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        var existing = Services.FirstOrDefault(sd => sd.ServiceType == serviceType);
        if (existing is not null)
        {
            throw new InvalidOperationException(
                $"{serviceType.Name} is already registered. Only one registration per service type is allowed.");
        }
    }

    /// <summary>Gets the application service collection.</summary>
    public IServiceCollection Services { get; }
}
