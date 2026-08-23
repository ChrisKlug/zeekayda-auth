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
    {
        ArgumentNullException.ThrowIfNull(services);

        var existing = services.FirstOrDefault(sd =>
            sd.ServiceType == typeof(ISigningKeySource) && Equals(sd.ServiceKey, SigningKeySourceServiceKey));

        if (existing is not null && existing.KeyedImplementationType != typeof(TSource))
        {
            throw new InvalidOperationException(
                $"A different ISigningKeySource ('{existing.KeyedImplementationType?.Name}') is " +
                $"already registered. Only one signing key source may be registered per application.");
        }

        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddKeyedSingleton<ISigningKeySource, TSource>(SigningKeySourceServiceKey);
        services.TryAddSingleton<ISigningKeyRing>(sp => new StaticSigningKeyRing(
            sp.GetRequiredKeyedService<ISigningKeySource>(SigningKeySourceServiceKey),
            sp.GetRequiredService<TimeProvider>()));

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, SigningKeyRingStartupVerifier>());

        return services;
    }
}
