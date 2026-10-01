using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering client secret hashers with <see cref="ZeeKayDaAuthCoreBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderHasherExtensions
{
    /// <summary>
    /// Registers a client secret hasher with ZeeKayDa.Auth.
    /// </summary>
    /// <typeparam name="THasher">
    /// The hasher implementation to register. Must implement <see cref="IClientSecretHasher"/>
    /// and be safe for concurrent use (singleton-safe).
    /// </typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="isDefault">
    /// When <see langword="true"/>, this hasher is used for creating new hashed secrets and for
    /// the timing-pad dummy credential. A single registered hasher is always the default
    /// regardless of this value; with multiple hashers, exactly one must set it to
    /// <see langword="true"/> or startup fails.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    public static ZeeKayDaAuthCoreBuilder AddClientSecretHasher<THasher>(
        this ZeeKayDaAuthCoreBuilder builder,
        bool isDefault = false)
        where THasher : class, IClientSecretHasher
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (builder.Services.Any(sd =>
                sd.ServiceType == typeof(IClientSecretHasher) &&
                sd.ImplementationType == typeof(THasher)))
            throw new InvalidOperationException(
                $"A hasher of type '{typeof(THasher).Name}' has already been registered. " +
                "Each IClientSecretHasher implementation type may only be registered once.");

        builder.Services.AddSingleton<IClientSecretHasher, THasher>();

        builder.Services.Configure<ClientSecretHasherRegistrationOptions>(
            options => options.Registrations.Add(
                new ClientSecretHasherRegistrationOptions.HasherRegistration(typeof(THasher), isDefault)));

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<ClientSecretHasherRegistrationOptions>,
                ClientSecretHasherOptionsValidator>());

        builder.Services.AddZeeKayDaOptions<ClientSecretHasherRegistrationOptions>();

        return builder;
    }

    /// <summary>
    /// Configures the built-in PBKDF2-HMAC-SHA256 client secret hasher, which
    /// <c>AddZeeKayDaAuth</c> always registers.
    /// </summary>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">Sets <see cref="Pbkdf2ClientSecretHasherOptions"/>.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <remarks>
    /// The iteration count must be between 600,000 and 2,000,000; startup fails otherwise. The
    /// options can equally be bound from configuration.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is <see langword="null"/>.
    /// </exception>
    public static TBuilder ConfigurePbkdf2ClientSecretHasher<TBuilder>(
        this TBuilder builder,
        Action<Pbkdf2ClientSecretHasherOptions> configure)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.Configure(configure);
        return builder;
    }
}
