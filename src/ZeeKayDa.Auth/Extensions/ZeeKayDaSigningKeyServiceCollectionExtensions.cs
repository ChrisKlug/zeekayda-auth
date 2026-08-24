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
    // framework's own TryAddKeyedSingleton by guessing a string key. This closes off *accidental*
    // collision and pre-emption — nobody guesses an object identity. It is not a boundary against
    // deliberate in-process code: code holding the IServiceCollection at composition time can read
    // this key straight off the framework's own ISigningKeySource descriptor, and code holding only
    // an IServiceProvider can reach the live instance via
    // GetKeyedServices<ISigningKeySource>(KeyedService.AnyKey) — neither needs reflection.
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

        ValidateNotAbstract<TSource>();

        var registeredByFactory = implementationFactory is not null;
        var existing = FindExistingRegistration(services);

        if (existing is not null)
            ValidateAgainstExisting<TSource>(existing, registeredByFactory);
        else
            services.AddKeyedSingleton(
                SigningKeySourceServiceKey, new SigningKeySourceRegistration(typeof(TSource), registeredByFactory));

        if (implementationFactory is null)
            services.TryAddKeyedSingleton<ISigningKeySource, TSource>(SigningKeySourceServiceKey);
        else
            services.TryAddKeyedSingleton<ISigningKeySource>(
                SigningKeySourceServiceKey, (sp, _) => implementationFactory(sp));

        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<ISigningKeyRing>(sp =>
        {
            var registrations = sp.GetKeyedServices<SigningKeySourceRegistration>(SigningKeySourceServiceKey)
                .ToArray();

            var recordedType = ValidateRegistrationSet(registrations);

            var source = sp.GetRequiredKeyedService<ISigningKeySource>(SigningKeySourceServiceKey);

            ValidateResolvedSource(recordedType, source);

            return new StaticSigningKeyRing(source, sp.GetRequiredService<TimeProvider>());
        });

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, SigningKeyRingStartupVerifier>());

        return services;
    }

    private static void ValidateNotAbstract<TSource>()
        where TSource : class, ISigningKeySource
    {
        if (!typeof(TSource).IsAbstract)
            return;

        throw new ArgumentException(
            $"'{typeof(TSource).FullName}' is an interface or abstract class and cannot be " +
            $"registered as a signing key source. Pass the concrete {nameof(ISigningKeySource)} " +
            "implementation type as TSource.", nameof(TSource));
    }

    private static void ValidateAgainstExisting<TSource>(
        SigningKeySourceRegistration existing, bool registeredByFactory)
        where TSource : class, ISigningKeySource
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
                "factory's configuration. Register the signing key source exactly once. If you did " +
                "not call this method twice yourself, a provider package's own " +
                "'Add<Provider>Signing()' call may already register this source via the factory " +
                "overload.");
        }
    }

    /// <summary>
    /// Validates the recorded registrations before the source instance is resolved, so a
    /// misconfigured composition fails before any of the winning registration's side effects run.
    /// </summary>
    /// <returns>The single distinct <see cref="SigningKeySourceRegistration.SourceType"/> in force.</returns>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when no registration is found, when more than one distinct source type is recorded, or
    /// when any recorded registration used the factory overload alongside another registration.
    /// </exception>
    private static Type ValidateRegistrationSet(IReadOnlyCollection<SigningKeySourceRegistration> registrations)
    {
        if (registrations.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.source_registration_mismatch",
                    "No signing key source registration was found for the resolved " +
                    $"{nameof(ISigningKeySource)}."));
        }

        var distinctTypes = registrations.Select(r => r.SourceType).Distinct().ToArray();

        if (distinctTypes.Length > 1)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.source_registration_mismatch",
                    $"{distinctTypes.Length} distinct signing key source types were found across " +
                    $"{registrations.Count} registrations. This happens when two independently-built " +
                    $"service collections, each of which called {nameof(AddZeeKayDaSigningKeySource)} " +
                    "for a different source, are composed into the same host. Only one signing key " +
                    "source may be registered per application."));
        }

        if (registrations.Count > 1 && registrations.Any(r => r.RegisteredByFactory))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.source_registration_mismatch",
                    $"{registrations.Count} registrations for signing key source " +
                    $"'{DisplayName(distinctTypes[0])}' were found, and at least one used the " +
                    "factory overload. A factory delegate can close over configuration, so composing " +
                    "collections that each registered the same source via the factory overload would " +
                    "silently discard all but one factory's configuration."));
        }

        return distinctTypes[0];
    }

    /// <summary>
    /// Validates the source instance DI resolved against the recorded registration's type.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the resolved <see cref="ISigningKeySource"/> is not an instance of the recorded
    /// registration's type.
    /// </exception>
    private static void ValidateResolvedSource(Type recordedType, ISigningKeySource source)
    {
        if (!recordedType.IsInstanceOfType(source))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.source_registration_mismatch",
                    $"The resolved signing key source '{DisplayName(source.GetType())}' does not " +
                    $"match the registered source type '{DisplayName(recordedType)}'."));
        }
    }

    private static SigningKeySourceRegistration? FindExistingRegistration(IServiceCollection services) =>
        (SigningKeySourceRegistration?)services
            .LastOrDefault(sd =>
                sd.ServiceType == typeof(SigningKeySourceRegistration) &&
                sd.IsKeyedService &&
                Equals(sd.ServiceKey, SigningKeySourceServiceKey))
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
