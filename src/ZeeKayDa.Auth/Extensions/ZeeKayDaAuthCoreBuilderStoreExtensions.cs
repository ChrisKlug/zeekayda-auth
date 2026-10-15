using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Stores;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering the token stores and the interaction store with
/// <see cref="ZeeKayDaAuthCoreBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthCoreBuilderStoreExtensions
{
    /// <summary>
    /// Registers a per-process interaction store for development and testing. A multi-instance host
    /// needs <see cref="AddDistributedCacheInteractionStore"/>.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>.
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// <see langword="true"/> only for test hosts running under a non-Development environment name; a
    /// critical log entry is still emitted on every startup.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an interaction store has already been registered. Only one store registration
    /// per interface is allowed.
    /// </exception>
    public static TBuilder AddInMemoryInteractionStore<TBuilder>(
        this TBuilder builder,
        bool allowOutsideDevelopment = false)
        where TBuilder : ZeeKayDaAuthCoreBuilder
        => AddInMemoryStore(
            builder,
            AddInteractionStore<InMemoryInteractionBackingStore>,
            InMemoryStoreVerifier.InteractionStoreName,
            allowOutsideDevelopment);

    /// <summary>
    /// Registers the interaction store over the host's <see cref="IDistributedCache"/>, such as Redis or
    /// SQL Server, which is enough for a multi-instance host.
    /// </summary>
    /// <remarks>
    /// Startup fails without a registered <see cref="IDistributedCache"/>, and outside Development on the
    /// per-process <c>MemoryDistributedCache</c> unless <paramref name="allowMemoryCacheOutsideDevelopment"/>
    /// is <see langword="true"/>.
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowMemoryCacheOutsideDevelopment">
    /// <see langword="true"/> only for test hosts running the memory cache under a non-Development
    /// environment name; a critical log entry is still emitted on every startup.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an interaction store has already been registered. Only one store registration
    /// per interface is allowed.
    /// </exception>
    public static TBuilder AddDistributedCacheInteractionStore<TBuilder>(
        this TBuilder builder,
        bool allowMemoryCacheOutsideDevelopment = false)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        AddInteractionStore<DistributedCacheInteractionBackingStore>(builder);
        builder.Services.AddScoped<IStartupActivator>(sp => new DistributedCacheInteractionStoreActivator(
            sp.GetRequiredService<IHostEnvironment>(),
            allowMemoryCacheOutsideDevelopment,
            sp.GetService<IDistributedCache>()));
        return builder;
    }

    /// <summary>Registers <typeparamref name="TStore"/> as the one interaction store.</summary>
    private static void AddInteractionStore<TStore>(ZeeKayDaAuthCoreBuilder builder)
        where TStore : class, IInteractionBackingStore
    {
        if (builder.Services.Any(descriptor => descriptor.ServiceType == typeof(IInteractionBackingStore)))
        {
            throw new InvalidOperationException(
                "An interaction store is already registered. Only one of AddInMemoryInteractionStore, " +
                "AddDistributedCacheInteractionStore or AddInMemoryStores may register it.");
        }

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.AddSingleton<IInteractionBackingStore, TStore>();
    }

    /// <summary>
    /// Registers <typeparamref name="T"/> as the singleton <see cref="IAuthorizationCodeBackingStore"/> underneath the
    /// framework's sealed coordinator. This is the production registration.
    /// </summary>
    /// <typeparam name="T">The backing store, constructed by the DI container.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IAuthorizationCodeBackingStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthCoreBuilder AddAuthorizationCodeStore<T>(this ZeeKayDaAuthCoreBuilder builder)
        where T : class, IAuthorizationCodeBackingStore
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IAuthorizationCodeBackingStore));
        builder.Services.AddSingleton<IAuthorizationCodeBackingStore, T>();
        builder.Services.TryAddSingleton<AuthorizationCodeStore>();

        return builder;
    }

    /// <summary>
    /// Registers <typeparamref name="T"/> as the singleton <see cref="IRefreshTokenBackingStore"/> underneath the
    /// framework's sealed coordinator. This is the production registration.
    /// </summary>
    /// <typeparam name="T">The backing store, constructed by the DI container.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IRefreshTokenBackingStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static ZeeKayDaAuthCoreBuilder AddRefreshTokenStore<T>(this ZeeKayDaAuthCoreBuilder builder)
        where T : class, IRefreshTokenBackingStore
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IRefreshTokenBackingStore));
        builder.Services.AddSingleton<IRefreshTokenBackingStore, T>();
        builder.Services.TryAddSingleton<RefreshTokenStore>();

        return builder;
    }

    /// <summary>
    /// Registers an in-memory authorization code store for development and testing. Tokens are lost on restart
    /// and reuse detection does not span instances.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>.
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// <see langword="true"/> only for test hosts running under a non-Development environment name; a
    /// critical log entry is still emitted on every startup.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IAuthorizationCodeBackingStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static TBuilder AddInMemoryAuthorizationCodeStore<TBuilder>(
        this TBuilder builder,
        bool allowOutsideDevelopment = false)
        where TBuilder : ZeeKayDaAuthCoreBuilder
        => AddInMemoryStore(
            builder,
            core => core.AddAuthorizationCodeStore<InMemoryAuthorizationCodeBackingStore>(),
            InMemoryStoreVerifier.AuthorizationCodeStoreName,
            allowOutsideDevelopment);

    /// <summary>
    /// Registers an in-memory refresh token store for development and testing. Tokens are lost on restart
    /// and reuse detection does not span instances.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>.
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// <see langword="true"/> only for test hosts running under a non-Development environment name; a
    /// critical log entry is still emitted on every startup.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IRefreshTokenBackingStore"/> has already been registered.
    /// Only one store registration per interface is allowed.
    /// </exception>
    public static TBuilder AddInMemoryRefreshTokenStore<TBuilder>(
        this TBuilder builder,
        bool allowOutsideDevelopment = false)
        where TBuilder : ZeeKayDaAuthCoreBuilder
        => AddInMemoryStore(
            builder,
            core => core.AddRefreshTokenStore<InMemoryRefreshTokenBackingStore>(),
            InMemoryStoreVerifier.RefreshTokenStoreName,
            allowOutsideDevelopment);

    /// <summary>
    /// Registers the in-memory authorization code, refresh token and interaction stores for development
    /// and testing, passing <paramref name="allowOutsideDevelopment"/> to all three.
    /// </summary>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
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
    /// Thrown when an <see cref="IAuthorizationCodeBackingStore"/>, an <see cref="IRefreshTokenBackingStore"/>
    /// or an interaction store has already been registered. Only one store registration per
    /// interface is allowed.
    /// </exception>
    public static TBuilder AddInMemoryStores<TBuilder>(
        this TBuilder builder,
        bool allowOutsideDevelopment = false)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment);
        builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment);
        builder.AddInMemoryInteractionStore(allowOutsideDevelopment);

        return builder;
    }

    private static TBuilder AddInMemoryStore<TBuilder>(
        TBuilder builder,
        Action<ZeeKayDaAuthCoreBuilder> addStore,
        string storeName,
        bool allowOutsideDevelopment)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        addStore(builder);
        builder.Services.AddScoped<IStartupVerifier>(sp => new InMemoryStoreVerifier(
            sp.GetRequiredService<IHostEnvironment>(), storeName, allowOutsideDevelopment));

        return builder;
    }
}
