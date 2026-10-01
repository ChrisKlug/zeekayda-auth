using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth;

/// <summary>
/// A builder for configuring the ZeeKayDa.Auth services that do not need HTTP.
/// </summary>
/// <remarks>
/// Returned by <c>AddZeeKayDaAuthCore(configure)</c>; <c>AddZeeKayDaAuth(configure)</c> returns the
/// derived ASP.NET Core builder. Use extension methods on this builder to register optional features
/// (signing keys, client stores, etc.) without adding properties to
/// <see cref="AuthorizationServerOptions"/>. An extension that returns the builder is generic over
/// it, <c>TBuilder AddX&lt;TBuilder&gt;(this TBuilder builder) where TBuilder : ZeeKayDaAuthCoreBuilder</c>,
/// so a chain started on a derived builder keeps its type.
/// </remarks>
public class ZeeKayDaAuthCoreBuilder
{
    internal ZeeKayDaAuthCoreBuilder(IServiceCollection services) => Services = services;

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
