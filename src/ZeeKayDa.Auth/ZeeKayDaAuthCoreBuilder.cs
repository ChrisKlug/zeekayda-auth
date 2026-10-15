using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth;

/// <summary>
/// A builder for the ZeeKayDa.Auth services that do not need HTTP, extended by registration methods
/// such as signing keys and client stores.
/// </summary>
/// <remarks>
/// An extension returning the builder is generic, <c>TBuilder AddX&lt;TBuilder&gt;(this TBuilder builder)
/// where TBuilder : ZeeKayDaAuthCoreBuilder</c>, so a chain on the derived ASP.NET Core builder keeps its type.
/// </remarks>
public class ZeeKayDaAuthCoreBuilder
{
    internal ZeeKayDaAuthCoreBuilder(IServiceCollection services) => Services = services;

    /// <summary>Gives the store registration methods their one-store-per-interface guarantee.</summary>
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
