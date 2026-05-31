using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// A builder for configuring ZeeKayDa.Auth services.
/// </summary>
/// <remarks>
/// Returned by <c>AddZeeKayDaAuth()</c>. Use extension methods on this builder to register
/// optional features (signing keys, client stores, etc.) without adding properties to
/// <see cref="ZeeKayDa.Auth.AuthorizationServerOptions"/>.
/// </remarks>
public sealed class ZeeKayDaAuthBuilder
{
    /// <summary>
    /// Initialises a new <see cref="ZeeKayDaAuthBuilder"/> instance.
    /// </summary>
    /// <param name="services">The application service collection.</param>
    internal ZeeKayDaAuthBuilder(IServiceCollection services)
    {
        Services = services;
    }

    /// <summary>Gets the application service collection.</summary>
    public IServiceCollection Services { get; }
}
