using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the application's signing key source with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderSigningKeySourceExtensions
{
    /// <summary>
    /// Registers <typeparamref name="TSource"/> as the application's signing key source, a
    /// <see cref="StaticSigningKeyRing"/> over it, and the startup check that reads the source and
    /// self-tests its signer once at host startup.
    /// </summary>
    /// <typeparam name="TSource">The <see cref="ISigningKeySource"/> implementation to register.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <typeparamref name="TSource"/> is an interface or abstract class, or implements
    /// <see cref="IAsyncDisposable"/> without also implementing <see cref="IDisposable"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source is already registered, whatever its type.
    /// </exception>
    /// <remarks>
    /// <para>
    /// A provider package calls this first from its own <c>Add&lt;Provider&gt;Signing()</c> method,
    /// then registers its options and helpers; the source takes them through its constructor. A
    /// second call always throws, even for the same type: the provider beside it has already
    /// applied its configuration, so a repeat is a second opinion about what signs the tokens.
    /// </para>
    /// <para>
    /// The source itself is never registered in the container: the ring constructs and owns it, so
    /// no application code can resolve it.
    /// </para>
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddSigningKeySource<TSource>(this ZeeKayDaAuthBuilder builder)
        where TSource : class, ISigningKeySource
    {
        ArgumentNullException.ThrowIfNull(builder);

        ValidateConcrete<TSource>();
        ValidateDisposalShape<TSource>();

        var services = builder.Services;
        if (services.LastOrDefault(sd => sd.ImplementationInstance is SigningKeySourceRegistration)
                ?.ImplementationInstance is SigningKeySourceRegistration existing)
        {
            ThrowAlreadyRegistered<TSource>(existing);
        }

        services.AddSingleton(new SigningKeySourceRegistration(typeof(TSource)));
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.AddSingleton<ISigningKeyRing>(sp =>
        {
            // The clock first: once the source exists, only the ring may own it, so nothing that
            // can still throw may run between creating it and handing it over.
            var timeProvider = sp.GetRequiredService<TimeProvider>();
            return new StaticSigningKeyRing(ActivatorUtilities.CreateInstance<TSource>(sp), timeProvider);
        });
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupActivator, SigningKeyRingStartupVerifier>());

        return builder;
    }

    private static void ValidateConcrete<TSource>()
    {
        if (typeof(TSource).IsAbstract)
        {
            throw new ArgumentException(
                $"'{typeof(TSource).FullName}' is an interface or abstract class and cannot be " +
                $"registered as a signing key source. Pass the concrete {nameof(ISigningKeySource)} " +
                "implementation type as TSource.", nameof(TSource));
        }
    }

    private static void ValidateDisposalShape<TSource>()
    {
        if (typeof(IAsyncDisposable).IsAssignableFrom(typeof(TSource))
            && !typeof(IDisposable).IsAssignableFrom(typeof(TSource)))
        {
            throw new ArgumentException(
                $"'{typeof(TSource).FullName}' implements {nameof(IAsyncDisposable)} but not " +
                $"{nameof(IDisposable)}. The ring that owns this source cannot know whether the host " +
                $"will dispose the service provider synchronously or asynchronously, so implement " +
                $"{nameof(IDisposable)} as well.", nameof(TSource));
        }
    }

    private static void ThrowAlreadyRegistered<TSource>(SigningKeySourceRegistration existing)
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

    private static string DisplayName(Type type) => $"{type.FullName} ({type.Assembly.GetName().Name})";
}

internal sealed record SigningKeySourceRegistration(Type SourceType);
