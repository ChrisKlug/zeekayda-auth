using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering JWT signing key providers with <see cref="ZeeKayDaAuthCoreBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthCoreBuilderSigningExtensions
{
    /// <summary>
    /// Registers a development-only signing key provider with an ephemeral in-memory RSA key, so
    /// tokens do not validate after a restart; <see cref="AddPersistedDevelopmentSigning"/> keeps the key.
    /// </summary>
    /// <remarks>
    /// Startup warns, and fails with <see cref="ZeeKayDaConfigurationException"/> outside
    /// <see cref="DevelopmentSigningOptions.AllowedEnvironments"/> (default <c>["Development"]</c>).
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">An optional callback to configure <see cref="DevelopmentSigningOptions"/>.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered — including by the other
    /// development registration method. Only one signing key provider is allowed.
    /// </exception>
    public static TBuilder AddInMemoryDevelopmentSigning<TBuilder>(
        this TBuilder builder,
        Action<DevelopmentSigningOptions>? configure = null)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        RegisterDevelopmentSigningKeys(builder, persistToDirectory: null, persist: false);

        if (configure is not null)
            builder.Services.AddOptions<DevelopmentSigningOptions>().Configure(configure);

        return builder;
    }

    /// <summary>
    /// Registers a development-only signing key provider that persists an RSA key to a local file,
    /// so tokens survive restarts.
    /// </summary>
    /// <remarks>
    /// Startup warns, and fails with <see cref="ZeeKayDaConfigurationException"/> outside
    /// <see cref="DevelopmentSigningOptions.AllowedEnvironments"/> (default <c>["Development"]</c>).
    /// The key file is owner-only; one with broader permissions is treated as compromised and fails startup.
    /// A directory this creates gets a <c>.gitignore</c> ignoring its contents; an existing one is left as it is.
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="persistTo">
    /// The key file's directory, or <see langword="null"/> for <c>{ContentRootPath}/.zeekayda/signing-keys/</c>.
    /// </param>
    /// <param name="configure">An optional callback to configure <see cref="DevelopmentSigningOptions"/>.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered — including by the other
    /// development registration method. Only one signing key provider is allowed.
    /// </exception>
    public static TBuilder AddPersistedDevelopmentSigning<TBuilder>(
        this TBuilder builder,
        string? persistTo = null,
        Action<DevelopmentSigningOptions>? configure = null)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        RegisterDevelopmentSigningKeys(builder, persistToDirectory: persistTo, persist: true);

        if (configure is not null)
            builder.Services.AddOptions<DevelopmentSigningOptions>().Configure(configure);

        return builder;
    }

    private static void RegisterDevelopmentSigningKeys(
        ZeeKayDaAuthCoreBuilder builder,
        string? persistToDirectory,
        bool persist)
    {
        // First, so a rejected second source leaves none of this call's configuration behind.
        builder.AddSigningKeySource<DevelopmentSigningKeySource>();
        builder.Services.TryAddSingleton<IDevelopmentSigningKeyFileSystem, LocalSigningKeyFileSystem>();

        builder.Services.AddZeeKayDaOptions<DevelopmentSigningOptions>();

        // Internal, so no caller callback can spoof the environment or give the in-memory key a directory.
        builder.Services.AddOptions<DevelopmentSigningOptions>().Configure<IHostEnvironment>((options, env) =>
        {
            options.EnvironmentName = env.EnvironmentName;

            if (persist)
            {
                options.PersistToDirectory = persistToDirectory
                    ?? Path.Join(env.ContentRootPath, ".zeekayda", "signing-keys");
            }
        });

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<DevelopmentSigningOptions>,
                AllowedDevEnvironmentsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, DevelopmentSigningKeyVerifier>());
    }
}
