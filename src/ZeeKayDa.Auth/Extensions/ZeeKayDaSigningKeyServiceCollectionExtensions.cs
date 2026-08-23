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
    /// <remarks>
    /// Idempotent with respect to the ring: every registration uses <c>TryAdd</c>, so calling this
    /// method more than once (for example, defensively from a third-party provider package's own
    /// registration method) registers exactly one <see cref="ISigningKeyRing"/>.
    /// </remarks>
    public static IServiceCollection AddZeeKayDaSigningKeySource<TSource>(this IServiceCollection services)
        where TSource : class, ISigningKeySource
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<ISigningKeySource, TSource>();
        services.TryAddSingleton<ISigningKeyRing, StaticSigningKeyRing>();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, SigningKeyRingStartupVerifier>());

        return services;
    }
}
