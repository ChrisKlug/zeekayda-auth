using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Extensions;

/// <summary>
/// Extension methods for registering the static signing key ring against an
/// <see cref="ISigningKeySource"/> implementation.
/// </summary>
public static class ZeeKayDaSigningKeyServiceCollectionExtensions
{
    // Registered under this key rather than as a plain singleton, so GetService<ISigningKeySource>()
    // returns null for arbitrary application code and only StaticSigningKeyRing's own factory below
    // can resolve it — closing off the ability to call CreateSignerAsync and dispose the live
    // production private-key handle outside the framework's own startup self-test.
    private const string SigningKeySourceServiceKey = "ZeeKayDa.Auth.Tokens.ISigningKeySource";

    /// <summary>
    /// Registers <typeparamref name="TSource"/> as the application's <see cref="ISigningKeySource"/>,
    /// a <see cref="StaticSigningKeyRing"/> over it, and the startup verification that reads the
    /// source and self-tests its signer once at host startup.
    /// </summary>
    /// <typeparam name="TSource">The <see cref="ISigningKeySource"/> implementation to register.</typeparam>
    /// <param name="services">The service collection to add services to.</param>
    /// <returns><paramref name="services"/> for chaining.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a different <see cref="ISigningKeySource"/> implementation is already registered.
    /// </exception>
    /// <remarks>
    /// Idempotent with respect to <typeparamref name="TSource"/>: calling this method again with the
    /// same source type (for example, defensively from a third-party provider package's own
    /// registration method) is a no-op. Calling it with a <em>different</em> source type throws,
    /// rather than silently keeping whichever was registered first. <see cref="ISigningKeySource"/>
    /// itself is registered under an internal key, not as a plain singleton — it is not resolvable
    /// via <c>GetService&lt;ISigningKeySource&gt;()</c>.
    /// </remarks>
    public static IServiceCollection AddZeeKayDaSigningKeySource<TSource>(this IServiceCollection services)
        where TSource : class, ISigningKeySource
        => AddCore<TSource>(services, implementationFactory: null);

    /// <summary>
    /// Registers <typeparamref name="TSource"/> as the application's <see cref="ISigningKeySource"/>,
    /// using <paramref name="implementationFactory"/> to construct it instead of DI activation, along
    /// with a <see cref="StaticSigningKeyRing"/> over it and the startup verification that reads the
    /// source and self-tests its signer once at host startup.
    /// </summary>
    /// <typeparam name="TSource">The <see cref="ISigningKeySource"/> implementation to register.</typeparam>
    /// <param name="services">The service collection to add services to.</param>
    /// <param name="implementationFactory">
    /// A factory that constructs the <typeparamref name="TSource"/> instance. Use this overload for a
    /// source that cannot be DI-activated — for example, one that needs a connection string, a slot
    /// name, or a pre-built client passed to its constructor.
    /// </param>
    /// <returns><paramref name="services"/> for chaining.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> or <paramref name="implementationFactory"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a different <see cref="ISigningKeySource"/> implementation is already registered.
    /// </exception>
    /// <remarks>
    /// Idempotent with respect to <typeparamref name="TSource"/>: calling this method again with the
    /// same source type — including with a different <paramref name="implementationFactory"/> — is a
    /// no-op, with the first factory winning. Calling it with a <em>different</em> source type throws,
    /// rather than silently keeping whichever was registered first. <see cref="ISigningKeySource"/>
    /// itself is registered under an internal key, not as a plain singleton — it is not resolvable
    /// via <c>GetService&lt;ISigningKeySource&gt;()</c>.
    /// </remarks>
    public static IServiceCollection AddZeeKayDaSigningKeySource<TSource>(
        this IServiceCollection services, Func<IServiceProvider, TSource> implementationFactory)
        where TSource : class, ISigningKeySource
    {
        ArgumentNullException.ThrowIfNull(implementationFactory);

        return AddCore(services, implementationFactory);
    }

    private static IServiceCollection AddCore<TSource>(
        IServiceCollection services, Func<IServiceProvider, TSource>? implementationFactory)
        where TSource : class, ISigningKeySource
    {
        ArgumentNullException.ThrowIfNull(services);

        var existing = (SigningKeySourceRegistration?)services
            .FirstOrDefault(sd => sd.ServiceType == typeof(SigningKeySourceRegistration))
            ?.ImplementationInstance;

        if (existing is not null && existing.SourceType != typeof(TSource))
        {
            throw new InvalidOperationException(
                $"Cannot register signing key source '{typeof(TSource).FullName}': " +
                $"'{existing.SourceType.FullName}' is already registered. Only one signing key " +
                $"source may be registered per application. Select between them with an ordinary " +
                $"if/else over the two registration calls rather than calling both.");
        }

        if (existing is null)
            services.AddSingleton(new SigningKeySourceRegistration(typeof(TSource)));

        if (implementationFactory is null)
            services.TryAddKeyedSingleton<ISigningKeySource, TSource>(SigningKeySourceServiceKey);
        else
            services.TryAddKeyedSingleton<ISigningKeySource>(
                SigningKeySourceServiceKey, (sp, _) => implementationFactory(sp));

        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<ISigningKeyRing>(sp => new StaticSigningKeyRing(
            sp.GetRequiredKeyedService<ISigningKeySource>(SigningKeySourceServiceKey),
            sp.GetRequiredService<TimeProvider>()));

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, SigningKeyRingStartupVerifier>());

        return services;
    }
}

/// <summary>
/// Records which <see cref="ISigningKeySource"/> implementation has been registered, so the
/// one-source-per-application guard in
/// <see cref="ZeeKayDaSigningKeyServiceCollectionExtensions"/> can recognize the incumbent even
/// when it was registered via the factory overload, for which
/// <see cref="ServiceDescriptor.ImplementationType"/> is <see langword="null"/>.
/// </summary>
/// <param name="SourceType">The <see cref="ISigningKeySource"/> implementation type registered.</param>
internal sealed record SigningKeySourceRegistration(Type SourceType);
