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
    /// concrete <see cref="ISigningKeySource"/> implementation, or when <typeparamref name="TSource"/>
    /// implements <see cref="IAsyncDisposable"/> without also implementing <see cref="IDisposable"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a different <see cref="ISigningKeySource"/> implementation is already registered,
    /// when <typeparamref name="TSource"/> is already registered via the factory overload, or when an
    /// <see cref="ISigningKeyRing"/> is already registered by something other than this method.
    /// </exception>
    /// <remarks>
    /// Idempotent with respect to <typeparamref name="TSource"/>: calling this method again with the
    /// same source type, both times via this overload, is a no-op. Calling it with a
    /// <em>different</em> source type throws, rather than silently keeping whichever was registered
    /// first, and so does calling it for a <typeparamref name="TSource"/> already registered via the
    /// factory overload — a factory delegate can close over configuration, so treating that as a
    /// no-op would silently discard it. Nothing is registered in the container for
    /// <see cref="ISigningKeySource"/> at all — the <see cref="ISigningKeyRing"/> factory constructs
    /// and owns the source directly, so it is not resolvable via
    /// <c>GetService&lt;ISigningKeySource&gt;()</c> or any other container lookup.
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
    /// concrete <see cref="ISigningKeySource"/> implementation, or when <typeparamref name="TSource"/>
    /// implements <see cref="IAsyncDisposable"/> without also implementing <see cref="IDisposable"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a different <see cref="ISigningKeySource"/> implementation is already registered,
    /// when <typeparamref name="TSource"/> is already registered, by either overload, or when an
    /// <see cref="ISigningKeyRing"/> is already registered by something other than this method.
    /// </exception>
    /// <remarks>
    /// A second registration of the same <typeparamref name="TSource"/> always throws when this
    /// overload is involved on either side — a factory delegate can close over configuration, and a
    /// second registration silently keeping the first factory's configuration is exactly the failure
    /// this method exists to prevent. Calling it with a <em>different</em> source type also throws.
    /// Nothing is registered in the container for <see cref="ISigningKeySource"/> at all — the
    /// <see cref="ISigningKeyRing"/> factory constructs and owns the source directly, so it is not
    /// resolvable via <c>GetService&lt;ISigningKeySource&gt;()</c> or any other container lookup.
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
        ValidateDisposalShape<TSource>();
        ValidateNoManualRingRegistration(services);

        var registeredByFactory = implementationFactory is not null;
        var existing = FindExistingRegistration(services);   // last UNKEYED marker descriptor

        if (existing is not null)
            ValidateAgainstExisting<TSource>(existing, registeredByFactory);
        else
            services.AddSingleton(new SigningKeySourceRegistration(typeof(TSource), registeredByFactory));

        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<ISigningKeyRing>(sp =>
        {
            ValidateRegistrationSet(sp.GetServices<SigningKeySourceRegistration>().ToArray());

            // The source is constructed last. Once StaticSigningKeyRing's constructor returns, the
            // ring is its only owner, so nothing between construction and that call may orphan it —
            // the constructor itself is the only thing left that can still reject the instance.
            var timeProvider = sp.GetRequiredService<TimeProvider>();
            var source = implementationFactory is null
                ? ActivatorUtilities.CreateInstance<TSource>(sp)
                : implementationFactory(sp);

            if (source is null)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.null_source",
                        $"The signing key source factory for '{DisplayName(typeof(TSource))}' " +
                        $"returned null. A signing key source factory must never return null."));
            }

            return new StaticSigningKeyRing(source, timeProvider);
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

    /// <summary>
    /// Rejects a source type that implements <see cref="IAsyncDisposable"/> without also implementing
    /// <see cref="IDisposable"/>, at registration time, before the collection is mutated.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// Thrown when <typeparamref name="TSource"/> implements <see cref="IAsyncDisposable"/> but not
    /// <see cref="IDisposable"/>.
    /// </exception>
    private static void ValidateDisposalShape<TSource>()
        where TSource : class, ISigningKeySource
    {
        if (!IsAsyncOnlyDisposable(typeof(TSource)))
            return;

        throw new ArgumentException(
            $"'{typeof(TSource).FullName}' implements {nameof(IAsyncDisposable)} but not " +
            $"{nameof(IDisposable)}. The ring that owns this source cannot know whether the host " +
            $"will dispose the service provider synchronously or asynchronously, so implement " +
            $"{nameof(IDisposable)} as well.", nameof(TSource));
    }

    /// <summary>
    /// The shared predicate behind <see cref="ValidateDisposalShape{TSource}"/>.
    /// </summary>
    private static bool IsAsyncOnlyDisposable(Type type) =>
        typeof(IAsyncDisposable).IsAssignableFrom(type) && !typeof(IDisposable).IsAssignableFrom(type);

    /// <summary>
    /// Rejects a composition where an <see cref="ISigningKeyRing"/> is already registered by
    /// something other than <see cref="AddZeeKayDaSigningKeySource{TSource}(IServiceCollection)"/> —
    /// otherwise <c>TryAddSingleton&lt;ISigningKeyRing&gt;</c> below silently keeps that registration,
    /// the source this call names is never constructed, and the marker recorded for it is never
    /// validated against anything.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="services"/> already contains a descriptor for
    /// <see cref="ISigningKeyRing"/> and no <see cref="SigningKeySourceRegistration"/> marker has been
    /// recorded yet, meaning that descriptor was not added by this extension.
    /// </exception>
    private static void ValidateNoManualRingRegistration(IServiceCollection services)
    {
        var hasManualRing = services.Any(sd => sd.ServiceType == typeof(ISigningKeyRing));
        var hasOwnMarker = FindExistingRegistration(services) is not null;

        if (hasManualRing && !hasOwnMarker)
        {
            throw new InvalidOperationException(
                $"An {nameof(ISigningKeyRing)} is already registered by something other than " +
                $"{nameof(AddZeeKayDaSigningKeySource)}. Only one signing key source may be " +
                $"registered per application. Remove the manual {nameof(ISigningKeyRing)} " +
                $"registration and register the signing key source through " +
                $"{nameof(AddZeeKayDaSigningKeySource)} instead.");
        }
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
    /// Validates the recorded registrations before the source instance is constructed, so a
    /// misconfigured composition fails before any of the winning registration's side effects run.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when no registration is found, when more than one distinct source type is recorded, or
    /// when any recorded registration used the factory overload alongside another registration.
    /// </exception>
    private static void ValidateRegistrationSet(IReadOnlyCollection<SigningKeySourceRegistration> registrations)
    {
        if (registrations.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.source_registration_mismatch",
                    $"No {nameof(SigningKeySourceRegistration)} was found."));
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
    }

    private static SigningKeySourceRegistration? FindExistingRegistration(IServiceCollection services) =>
        (SigningKeySourceRegistration?)services
            .LastOrDefault(sd => sd.ImplementationInstance is SigningKeySourceRegistration)
            ?.ImplementationInstance;

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
