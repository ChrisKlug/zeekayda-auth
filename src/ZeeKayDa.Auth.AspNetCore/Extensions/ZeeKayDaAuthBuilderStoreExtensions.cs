using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;
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
    /// recommended registration path for production use (ADR 0013 §4).
    /// </summary>
    /// <typeparam name="T">
    /// The concrete type that implements <see cref="IAuthorizationCodeBackingStore"/>. Must be a
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
        where T : class, IAuthorizationCodeBackingStore
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IAuthorizationCodeStore));
        builder.Services.AddSingleton<IAuthorizationCodeBackingStore, T>();
        builder.Services.AddSingleton<IAuthorizationCodeStore, AuthorizationCodeStore>();

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

    /// <summary>
    /// Registers an in-memory token store for development and testing only. All tokens are
    /// lost on process restart, and single-use enforcement and reuse detection are disabled
    /// across multiple instances. A startup warning is emitted before the first request.
    /// Do not use in production.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>. This gate is
    /// enforced independently of any other in-memory store registration on the same builder — see
    /// ADR 0008 §5.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// Set to <see langword="true"/> only in test hosts that intentionally run under a
    /// non-Development environment name (e.g. integration test hosts configured as
    /// <c>Production</c>). A <see cref="Microsoft.Extensions.Logging.LogLevel.Critical"/> entry is
    /// still emitted on every startup so the override is always visible in logs. Defaults to
    /// <see langword="false"/>.
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
        builder.Services.AddSingleton<IHostedService>(sp => new InMemoryStoreWarningService(
            sp.GetRequiredService<IHostEnvironment>(),
            InMemoryStoreWarningService.AuthorizationCodeStoreName,
            allowOutsideDevelopment,
            sp.GetRequiredService<ISanitizingLogger<InMemoryStoreWarningService>>()));

        return builder;
    }

    /// <summary>
    /// Registers an in-memory token store for development and testing only. All tokens are
    /// lost on process restart, and single-use enforcement and reuse detection are disabled
    /// across multiple instances. A startup warning is emitted before the first request.
    /// Do not use in production.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>. This gate is
    /// enforced independently of any other in-memory store registration on the same builder — see
    /// ADR 0008 §5.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// Set to <see langword="true"/> only in test hosts that intentionally run under a
    /// non-Development environment name (e.g. integration test hosts configured as
    /// <c>Production</c>). A <see cref="Microsoft.Extensions.Logging.LogLevel.Critical"/> entry is
    /// still emitted on every startup so the override is always visible in logs. Defaults to
    /// <see langword="false"/>.
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
        builder.Services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        builder.Services.AddSingleton<IHostedService>(sp => new InMemoryStoreWarningService(
            sp.GetRequiredService<IHostEnvironment>(),
            InMemoryStoreWarningService.RefreshTokenStoreName,
            allowOutsideDevelopment,
            sp.GetRequiredService<ISanitizingLogger<InMemoryStoreWarningService>>()));

        return builder;
    }

    /// <summary>
    /// Registers an in-memory token store for development and testing only. All tokens are
    /// lost on process restart, and single-use enforcement and reuse detection are disabled
    /// across multiple instances. A startup warning is emitted before the first request.
    /// Do not use in production.
    /// </summary>
    /// <remarks>
    /// Outside a Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <paramref name="allowOutsideDevelopment"/> is <see langword="true"/>. The value is
    /// passed through to both <see cref="AddInMemoryAuthorizationCodeStore"/> and
    /// <see cref="AddInMemoryRefreshTokenStore"/>, each of which gates on it independently — see
    /// ADR 0008 §5.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="allowOutsideDevelopment">
    /// Set to <see langword="true"/> only in test hosts that intentionally run under a
    /// non-Development environment name (e.g. integration test hosts configured as
    /// <c>Production</c>). A <see cref="Microsoft.Extensions.Logging.LogLevel.Critical"/> entry is
    /// still emitted on every startup so the override is always visible in logs. Defaults to
    /// <see langword="false"/>.
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
    /// Multi-instance production deployments MUST replace these stores with an atomic implementation;
    /// see ADR 0008 §8.
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
            ServiceDescriptor.Singleton<IHostedService, DistributedCacheStoreStartupValidator>());

        return builder;
    }

    /// <summary>
    /// Registers a non-atomic <see cref="IDistributedCache"/>-backed default suitable for dev/test only.
    /// Multi-instance production deployments MUST replace these stores with an atomic implementation;
    /// see ADR 0008 §8.
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
        builder.Services.AddSingleton<IRefreshTokenStore, DistributedCacheRefreshTokenStore>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, DistributedCacheStoreStartupValidator>());

        return builder;
    }

    /// <summary>
    /// Registers a non-atomic <see cref="IDistributedCache"/>-backed default suitable for dev/test only.
    /// Multi-instance production deployments MUST replace these stores with an atomic implementation;
    /// see ADR 0008 §8.
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
