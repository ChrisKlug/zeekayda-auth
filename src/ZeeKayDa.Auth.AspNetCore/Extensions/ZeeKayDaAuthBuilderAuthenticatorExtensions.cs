using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

namespace ZeeKayDa.Auth.AspNetCore.Extensions;

/// <summary>
/// Extension methods for registering client authenticators with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderAuthenticatorExtensions
{
    /// <summary>
    /// Registers a custom client authenticator with ZeeKayDa.Auth.
    /// </summary>
    /// <typeparam name="TAuthenticator">
    /// The authenticator implementation to register. Must implement <see cref="IClientAuthenticator"/>
    /// and be safe for concurrent use (singleton-safe).
    /// </typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <typeparamref name="TAuthenticator"/> has already been registered.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddClientAuthenticator<TAuthenticator>(
        this ZeeKayDaAuthBuilder builder)
        where TAuthenticator : class, IClientAuthenticator
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (builder.Services.Any(sd =>
                sd.ServiceType == typeof(IClientAuthenticator) &&
                sd.ImplementationType == typeof(TAuthenticator)))
            throw new InvalidOperationException(
                $"An authenticator of type '{typeof(TAuthenticator).Name}' has already been registered. " +
                "Each IClientAuthenticator implementation type may only be registered once.");

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IClientAuthenticator, TAuthenticator>());

        return builder;
    }
}
