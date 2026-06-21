using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Stores;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering token stores with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderStoreExtensions
{
    /// <summary>
    /// Registers <typeparamref name="T"/> as the singleton <see cref="IAuthorizationCodeStore"/> implementation. This is the recommended registration path for production use.
    /// </summary>
    /// <typeparam name="T">
    /// The concrete type that implements <see cref="IAuthorizationCodeStore"/>. Must be a
    /// reference type with a publicly accessible constructor so that the DI container can
    /// instantiate it.
    /// </typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IAuthorizationCodeStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddAuthorizationCodeStore<T>(this ZeeKayDaAuthBuilder builder)
        where T : class, IAuthorizationCodeStore
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IAuthorizationCodeStore));
        builder.Services.AddSingleton<IAuthorizationCodeStore, T>();

        return builder;
    }

    /// <summary>
    /// Registers <typeparamref name="T"/> as the singleton <see cref="IRefreshTokenStore"/> implementation. This is the recommended registration path for production use.
    /// </summary>
    /// <typeparam name="T">
    /// The concrete type that implements <see cref="IRefreshTokenStore"/>. Must be a
    /// reference type with a publicly accessible constructor so that the DI container can
    /// instantiate it.
    /// </typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IRefreshTokenStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddRefreshTokenStore<T>(this ZeeKayDaAuthBuilder builder)
        where T : class, IRefreshTokenStore
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IRefreshTokenStore));
        builder.Services.AddSingleton<IRefreshTokenStore, T>();

        return builder;
    }
}
