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
    // Both ISigningKeySource and its registration marker are resolved only through this private,
    // unnameable key. GetService<ISigningKeySource>() and IEnumerable<ISigningKeySource> return
    // nothing for arbitrary application code, and nothing outside this assembly can pre-empt the
    // framework's own TryAddKeyedSingleton by guessing a string key — closing off the ability to
    // resolve ISigningKeySource, and therefore the live production private-key handle, outside the
    // framework's own startup self-test.
    private static readonly object SigningKeySourceServiceKey = new();

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
    /// <exception cref="ArgumentException">
    /// Thrown when <typeparamref name="TSource"/> is an interface or abstract class rather than a
    /// concrete <see cref="ISigningKeySource"/> implementation.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a different <see cref="ISigningKeySource"/> implementation is already registered,
    /// or when <typeparamref name="TSource"/> is already registered via the factory overload.
    /// </exception>
    /// <remarks>
    /// Idempotent with respect to <typeparamref name="TSource"/>: calling this method again with the
    /// same source type, both times via this overload, is a no-op. Calling it with a
    /// <em>different</em> source type throws, rather than silently keeping whichever was registered
    /// first, and so does calling it for a <typeparamref name="TSource"/> already registered via the
    /// factory overload — a factory delegate can close over configuration, so treating that as a
    /// no-op would silently discard it. <see cref="ISigningKeySource"/> itself is registered under an
    /// internal key, not as a plain singleton — it is not resolvable via
    /// <c>GetService&lt;ISigningKeySource&gt;()</c>.
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
    /// <exception cref="ArgumentException">
    /// Thrown when <typeparamref name="TSource"/> is an interface or abstract class rather than a
    /// concrete <see cref="ISigningKeySource"/> implementation.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a different <see cref="ISigningKeySource"/> implementation is already registered,
    /// or when <typeparamref name="TSource"/> is already registered, by either overload.
    /// </exception>
    /// <remarks>
    /// A second registration of the same <typeparamref name="TSource"/> always throws when this
    /// overload is involved on either side — a factory delegate can close over configuration, and a
    /// second registration silently keeping the first factory's configuration is exactly the failure
    /// this method exists to prevent. Calling it with a <em>different</em> source type also throws.
    /// <see cref="ISigningKeySource"/> itself is registered under an internal key, not as a plain
    /// singleton — it is not resolvable via <c>GetService&lt;ISigningKeySource&gt;()</c>.
    /// </remarks>
    public static IServiceCollection AddZeeKayDaSigningKeySource<TSource>(
        this IServiceCollection services, Func<IServiceProvider, TSource> implementationFactory)
        where TSource : class, ISigningKeySource
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        return AddCore(services, implementationFactory);
    }

    private static IServiceCollection AddCore<TSource>(
        IServiceCollection services, Func<IServiceProvider, TSource>? implementationFactory)
        where TSource : class, ISigningKeySource
    {
        ArgumentNullException.ThrowIfNull(services);

        if (typeof(TSource).IsAbstract)
        {
            throw new ArgumentException(
                $"'{typeof(TSource).FullName}' is an interface or abstract class and cannot be " +
                $"registered as a signing key source. Pass the concrete {nameof(ISigningKeySource)} " +
                "implementation type as TSource.");
        }

        var registeredByFactory = implementationFactory is not null;
        var existing = FindExistingRegistration(services);

        if (existing is not null)
        {
            if (existing.SourceType != typeof(TSource))
            {
                throw new InvalidOperationException(
                    $"Cannot register signing key source '{DisplayName(typeof(TSource))}': " +
                    $"'{DisplayName(existing.SourceType)}' is already registered. Only one signing " +
                    "key source may be registered per application. Select between them with an " +
                    "ordinary if/else over the two registration calls rather than calling both.");
            }

            if (existing.RegisteredByFactory || registeredByFactory)
            {
                throw new InvalidOperationException(
                    $"'{DisplayName(typeof(TSource))}' is already registered as the signing key " +
                    "source, and at least one of the two registrations used the factory overload. " +
                    "A factory delegate can close over configuration, so a second factory " +
                    "registration for the same source type would silently discard the second " +
                    "factory's configuration. Register the signing key source exactly once.");
            }
        }
        else
        {
            services.AddKeyedSingleton(
                SigningKeySourceServiceKey, new SigningKeySourceRegistration(typeof(TSource), registeredByFactory));
        }

        if (implementationFactory is null)
            services.TryAddKeyedSingleton<ISigningKeySource, TSource>(SigningKeySourceServiceKey);
        else
            services.TryAddKeyedSingleton<ISigningKeySource>(
                SigningKeySourceServiceKey, (sp, _) => implementationFactory(sp));

        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<ISigningKeyRing>(sp =>
        {
            var source = sp.GetRequiredKeyedService<ISigningKeySource>(SigningKeySourceServiceKey);
            var recordedType = sp
                .GetRequiredKeyedService<SigningKeySourceRegistration>(SigningKeySourceServiceKey)
                .SourceType;

            if (!recordedType.IsInstanceOfType(source))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.source_registration_mismatch",
                        $"The resolved signing key source '{DisplayName(source.GetType())}' does " +
                        $"not match the registered source type '{DisplayName(recordedType)}'. This " +
                        $"indicates two different {nameof(ISigningKeySource)} registrations were " +
                        "composed into the same service collection."));
            }

            return new StaticSigningKeyRing(source, sp.GetRequiredService<TimeProvider>());
        });

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, SigningKeyRingStartupVerifier>());

        return services;
    }

    private static SigningKeySourceRegistration? FindExistingRegistration(IServiceCollection services) =>
        (SigningKeySourceRegistration?)services
            .FirstOrDefault(sd => sd.ServiceType == typeof(SigningKeySourceRegistration) && sd.IsKeyedService)
            ?.KeyedImplementationInstance;

    private static string DisplayName(Type type) => $"{type.FullName} ({type.Assembly.GetName().Name})";
}

/// <summary>
/// Records the <see cref="ISigningKeySource"/> implementation type registered via
/// <see cref="ZeeKayDaSigningKeyServiceCollectionExtensions"/>, and whether that registration used
/// the factory overload.
/// </summary>
/// <param name="SourceType">The registered <see cref="ISigningKeySource"/> implementation type.</param>
/// <param name="RegisteredByFactory">
/// <see langword="true"/> if the source was registered via the factory overload;
/// <see langword="false"/> if it was registered via the type overload for DI activation.
/// </param>
internal sealed record SigningKeySourceRegistration(Type SourceType, bool RegisteredByFactory);
