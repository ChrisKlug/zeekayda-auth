using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth;

/// <summary>
/// A builder for configuring ZeeKayDa.Auth services.
/// </summary>
/// <remarks>
/// Returned by <c>AddZeeKayDaAuth()</c> and <c>AddZeeKayDaAuthCore()</c>. Use extension methods on this builder to register
/// optional features (signing keys, client stores, etc.) without adding properties to
/// <see cref="AuthorizationServerOptions"/>.
/// </remarks>
public sealed class ZeeKayDaAuthBuilder
{
    internal ZeeKayDaAuthBuilder(IServiceCollection services) => Services = services;

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> if <paramref name="serviceType"/> is
    /// already registered in <see cref="Services"/>.
    /// </summary>
    /// <remarks>
    /// Used only inside the framework's public store registration methods, which is where a store
    /// of any origin gets the one-store-per-interface guarantee.
    /// </remarks>
    /// <param name="serviceType">The service interface type to check for duplicate registration.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="serviceType"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a <see cref="ServiceDescriptor"/> with
    /// <see cref="ServiceDescriptor.ServiceType"/> equal to <paramref name="serviceType"/>
    /// already exists in <see cref="Services"/>.
    /// </exception>
    internal void ThrowIfAlreadyRegistered(Type serviceType)
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
