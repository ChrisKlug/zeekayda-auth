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
    /// Thrown when any <see cref="ISigningKeySource"/> is already registered — including
    /// <typeparamref name="TSource"/> itself, by either overload — or when an
    /// <see cref="ISigningKeyRing"/> is already registered by something other than this method.
    /// </exception>
    /// <remarks>
    /// An application registers exactly one signing key source, so a second call always throws,
    /// whichever overload either call used and whether or not the source type is the same. A repeat
    /// registration is not idempotent even when the type matches: a provider's own
    /// <c>Add&lt;Provider&gt;Signing()</c> method registers the source <em>and</em> configures an
    /// options object beside it, so a second call that looked like a no-op here would still have
    /// applied a second configuration callback — the two calls are two opinions about what signs the
    /// application's tokens. Select between them with an ordinary if/else rather than calling both.
    /// Nothing is registered in the container for <see cref="ISigningKeySource"/> at all — the
    /// <see cref="ISigningKeyRing"/> factory constructs and owns the source directly, so it is not
    /// resolvable via <c>GetService&lt;ISigningKeySource&gt;()</c> or any other container lookup.
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
    /// Thrown when any <see cref="ISigningKeySource"/> is already registered — including
    /// <typeparamref name="TSource"/> itself, by either overload — or when an
    /// <see cref="ISigningKeyRing"/> is already registered by something other than this method.
    /// </exception>
    /// <remarks>
    /// An application registers exactly one signing key source, so a second call always throws,
    /// whichever overload either call used and whether or not the source type is the same. Nothing
    /// is registered in the container for <see cref="ISigningKeySource"/> at all — the
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

        var existing = FindExistingRegistration(services);   // last UNKEYED marker descriptor

        if (existing is not null)
            ThrowAlreadyRegistered<TSource>(existing);

        services.AddSingleton(new SigningKeySourceRegistration(typeof(TSource)));

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
    /// Rejects a composition where an unkeyed <see cref="ISigningKeyRing"/> is already registered by
    /// something other than <see cref="AddZeeKayDaSigningKeySource{TSource}(IServiceCollection)"/> —
    /// otherwise <c>TryAddSingleton&lt;ISigningKeyRing&gt;</c> below silently keeps that registration,
    /// the source this call names is never constructed, and the marker recorded for it is never
    /// validated against anything. A keyed <see cref="ISigningKeyRing"/> descriptor is ignored: it can
    /// never win the unkeyed resolution this method and the framework both use.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="services"/> already contains an unkeyed descriptor for
    /// <see cref="ISigningKeyRing"/> and no <see cref="SigningKeySourceRegistration"/> marker has been
    /// recorded yet, meaning that descriptor was not added by this extension.
    /// </exception>
    private static void ValidateNoManualRingRegistration(IServiceCollection services)
    {
        var manualRing = services.LastOrDefault(
            sd => sd.ServiceType == typeof(ISigningKeyRing) && !sd.IsKeyedService);
        var hasOwnMarker = FindExistingRegistration(services) is not null;

        if (manualRing is null || hasOwnMarker)
            return;

        throw new InvalidOperationException(
            $"An {nameof(ISigningKeyRing)} is already registered ({DescribeRingDescriptor(manualRing)}), " +
            $"and no {nameof(SigningKeySourceRegistration)} marker was found for it. Either it was " +
            $"registered by something other than {nameof(AddZeeKayDaSigningKeySource)}, or this " +
            $"collection's own marker for it was removed after {nameof(AddZeeKayDaSigningKeySource)} " +
            "ran. Only one signing key source may be registered per application. Remove the manual " +
            $"{nameof(ISigningKeyRing)} registration and register the signing key source through " +
            $"{nameof(AddZeeKayDaSigningKeySource)} instead.");
    }

    /// <summary>
    /// Describes an <see cref="ISigningKeyRing"/> <see cref="ServiceDescriptor"/> for an error
    /// message: its implementation type when one is known, or the shape of the registration (an
    /// instance or a factory) when it is not.
    /// </summary>
    private static string DescribeRingDescriptor(ServiceDescriptor descriptor) => descriptor switch
    {
        { ImplementationType: { } type } => DisplayName(type),
        { ImplementationInstance: { } instance } => $"an instance of {DisplayName(instance.GetType())}",
        { ImplementationFactory: not null } => "a factory registration with no known implementation type",
        _ => "a registration with no known implementation type",
    };

    /// <summary>
    /// Rejects a second signing key source registration, whichever overload either call used and
    /// whether or not the source type matches. A repeat registration of the same type is not treated
    /// as a no-op: the registration call is only half of what a provider's
    /// <c>Add&lt;Provider&gt;Signing()</c> method does, and the options configuration beside it would
    /// have been applied twice.
    /// </summary>
    /// <exception cref="InvalidOperationException">Always.</exception>
    private static void ThrowAlreadyRegistered<TSource>(SigningKeySourceRegistration existing)
        where TSource : class, ISigningKeySource
    {
        var subject = existing.SourceType == typeof(TSource)
            ? $"'{DisplayName(typeof(TSource))}' is already registered as the signing key source"
            : $"Cannot register signing key source '{DisplayName(typeof(TSource))}': " +
              $"'{DisplayName(existing.SourceType)}' is already registered";

        throw new InvalidOperationException(
            $"{subject}. Only one signing key source may be registered per application. Select " +
            "between them with an ordinary if/else over the two registration calls rather than " +
            "calling both. If you did not call this method twice yourself, a provider package's own " +
            "'Add<Provider>Signing()' call may already register a source.");
    }

    /// <summary>
    /// Validates the recorded registrations before the source instance is constructed, so a
    /// misconfigured composition fails before any of the winning registration's side effects run.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when no registration is found, or when more than one registration is recorded.
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

        if (registrations.Count > 1)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.source_registration_mismatch",
                    $"{registrations.Count} registrations for signing key source " +
                    $"'{DisplayName(distinctTypes[0])}' were found. This happens when two " +
                    "independently-built service collections, each of which registered that source, " +
                    "are composed into the same host. Only one signing key source may be registered " +
                    "per application: each of those collections also configured the source's options, " +
                    "and only one of those configurations describes what the application actually " +
                    "signs with."));
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
/// <see cref="ZeeKayDaSigningKeyServiceCollectionExtensions"/>.
/// </summary>
/// <param name="SourceType">The registered <see cref="ISigningKeySource"/> implementation type.</param>
internal sealed record SigningKeySourceRegistration(Type SourceType);
