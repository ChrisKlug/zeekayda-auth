using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Stores;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering token stores with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderStoreExtensions
{
    /// <summary>
    /// Registers <typeparamref name="T"/> as the singleton <see cref="IAuthorizationCodeBackingStore"/>
    /// implementation, wired underneath the framework's sealed coordinator. This is the
    /// recommended registration path for production use.
    /// </summary>
    /// <typeparam name="T">
    /// The concrete type implementing <see cref="IAuthorizationCodeBackingStore"/>. Must have a
    /// publicly accessible constructor so the DI container can instantiate it.
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
        where T : class, IAuthorizationCodeBackingStore
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IAuthorizationCodeStore));
        builder.Services.AddSingleton<IAuthorizationCodeBackingStore, T>();
        builder.Services.AddSingleton<IAuthorizationCodeStore, AuthorizationCodeStore>();

        return builder;
    }

    /// <summary>
    /// Registers <typeparamref name="T"/> as the singleton <see cref="IRefreshTokenGrantStore"/>
    /// implementation, wired underneath the framework's sealed coordinator. This is the
    /// recommended registration path for production use.
    /// </summary>
    /// <typeparam name="T">
    /// The concrete type implementing <see cref="IRefreshTokenGrantStore"/>. Must have a
    /// publicly accessible constructor so the DI container can instantiate it.
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
    public static ZeeKayDaAuthBuilder AddRefreshTokenGrantStore<T>(this ZeeKayDaAuthBuilder builder)
        where T : class, IRefreshTokenGrantStore
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IRefreshTokenStore));
        builder.Services.AddSingleton<IRefreshTokenGrantStore, T>();
        builder.Services.AddSingleton<IRefreshTokenStore, RefreshTokenStore>();

        return builder;
    }

    /// <summary>
    /// Registers an in-memory authorization code store for development and testing only. Tokens
    /// are lost on process restart and reuse detection does not span multiple instances. Do not
    /// use in production.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// Set to <see langword="true"/> only for test hosts that intentionally run under a
    /// non-Development environment name. A critical log entry is still emitted on every startup
    /// so the override remains visible. Defaults to <see langword="false"/>.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IAuthorizationCodeStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddInMemoryAuthorizationCodeStore(
        this ZeeKayDaAuthBuilder builder,
        bool allowOutsideDevelopment = false)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IAuthorizationCodeStore));
        builder.Services.AddSingleton<IAuthorizationCodeBackingStore, InMemoryAuthorizationCodeBackingStore>();
        builder.Services.AddSingleton<IAuthorizationCodeStore, AuthorizationCodeStore>();
        builder.Services.AddSingleton<IStartupVerifier>(sp => new InMemoryStoreVerifier(
            sp.GetRequiredService<IHostEnvironment>(),
            InMemoryStoreVerifier.AuthorizationCodeStoreName,
            allowOutsideDevelopment));

        return builder;
    }

    /// <summary>
    /// Registers an in-memory refresh token store for development and testing only. Tokens are
    /// lost on process restart and reuse detection does not span multiple instances. Do not use
    /// in production.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// Set to <see langword="true"/> only for test hosts that intentionally run under a
    /// non-Development environment name. A critical log entry is still emitted on every startup
    /// so the override remains visible. Defaults to <see langword="false"/>.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IRefreshTokenStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddInMemoryRefreshTokenStore(
        this ZeeKayDaAuthBuilder builder,
        bool allowOutsideDevelopment = false)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IRefreshTokenStore));
        builder.Services.AddSingleton<IRefreshTokenGrantStore, InMemoryRefreshTokenGrantStore>();
        builder.Services.AddSingleton<IRefreshTokenStore, RefreshTokenStore>();
        builder.Services.AddSingleton<IStartupVerifier>(sp => new InMemoryStoreVerifier(
            sp.GetRequiredService<IHostEnvironment>(),
            InMemoryStoreVerifier.RefreshTokenStoreName,
            allowOutsideDevelopment));

        return builder;
    }

    /// <summary>
    /// Registers in-memory authorization code and refresh token stores for development and
    /// testing only. Do not use in production.
    /// </summary>
    /// <remarks>
    /// Combines <see cref="AddInMemoryAuthorizationCodeStore"/> and
    /// <see cref="AddInMemoryRefreshTokenStore"/>, passing <paramref name="allowOutsideDevelopment"/>
    /// through to both.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// Set to <see langword="true"/> only for test hosts that intentionally run under a
    /// non-Development environment name. Defaults to <see langword="false"/>.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IAuthorizationCodeStore"/> or <see cref="IRefreshTokenStore"/>
    /// has already been registered. Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddInMemoryStores(
        this ZeeKayDaAuthBuilder builder,
        bool allowOutsideDevelopment = false)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment);
        builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment);

        return builder;
    }

    /// <summary>
    /// Registers a non-atomic <see cref="IDistributedCache"/>-backed default suitable for dev/test only.
    /// Multi-instance production deployments MUST replace these stores with an atomic implementation.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IAuthorizationCodeStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddDistributedCacheAuthorizationCodeStore(this ZeeKayDaAuthBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IAuthorizationCodeStore));
        builder.Services.AddSingleton<IAuthorizationCodeBackingStore, DistributedCacheAuthorizationCodeBackingStore>();
        builder.Services.AddSingleton<IAuthorizationCodeStore, AuthorizationCodeStore>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupActivator, DistributedCacheStoreStartupValidator>());

        return builder;
    }

    /// <summary>
    /// Registers a non-atomic <see cref="IDistributedCache"/>-backed default suitable for dev/test only.
    /// Multi-instance production deployments MUST replace these stores with an atomic implementation.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IRefreshTokenStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddDistributedCacheRefreshTokenStore(this ZeeKayDaAuthBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IRefreshTokenStore));
        builder.Services.AddSingleton<IRefreshTokenGrantStore, DistributedCacheRefreshTokenGrantStore>();
        builder.Services.AddSingleton<IRefreshTokenStore, RefreshTokenStore>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupActivator, DistributedCacheStoreStartupValidator>());

        return builder;
    }

    /// <summary>
    /// Registers a non-atomic <see cref="IDistributedCache"/>-backed default suitable for dev/test only.
    /// Multi-instance production deployments MUST replace these stores with an atomic implementation.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IAuthorizationCodeStore"/> or <see cref="IRefreshTokenStore"/>
    /// has already been registered. Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddDistributedCacheTokenStores(this ZeeKayDaAuthBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddDistributedCacheAuthorizationCodeStore();
        builder.AddDistributedCacheRefreshTokenStore();

        return builder;
    }
}
