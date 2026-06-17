using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering client secret hashers with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderHasherExtensions
{
    /// <summary>
    /// Registers the built-in PBKDF2-HMAC-SHA256 hasher as the sole client secret hasher.
    /// Equivalent to calling <see cref="AddSecretsHasher{THasher}"/> with
    /// <see cref="Pbkdf2ClientSecretHasher"/> as the type parameter.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">
    /// Optional delegate to configure <see cref="Pbkdf2ClientSecretHasherOptions"/>. When
    /// <see langword="null"/>, the default iteration count of 600,000 is used.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPbkdf2SecretsHasher(
        this ZeeKayDaAuthBuilder builder,
        Action<Pbkdf2ClientSecretHasherOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (configure is not null)
            builder.Services.Configure(configure);

        return builder.AddSecretsHasher<Pbkdf2ClientSecretHasher>();
    }

    /// <summary>
    /// Registers a client secret hasher with ZeeKayDa.Auth.
    /// </summary>
    /// <typeparam name="THasher">
    /// The hasher implementation to register. Must implement <see cref="IClientSecretHasher"/>
    /// and be safe for concurrent use (singleton-safe).
    /// </typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="isDefault">
    /// <para>
    /// When <see langword="true"/>, this hasher is used when creating new hashed secrets and
    /// when generating the timing-pad dummy credential at startup.
    /// </para>
    /// <para>
    /// When only one hasher is registered, it is automatically the default regardless of this
    /// value. When multiple hashers are registered, exactly one must have
    /// <paramref name="isDefault"/> set to <see langword="true"/>; zero or multiple defaults
    /// cause a startup failure.
    /// </para>
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddSecretsHasher<THasher>(
        this ZeeKayDaAuthBuilder builder,
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

        builder.Services.AddOptions<ClientSecretHasherRegistrationOptions>()
            .ValidateOnStart();

        return builder;
    }
}
