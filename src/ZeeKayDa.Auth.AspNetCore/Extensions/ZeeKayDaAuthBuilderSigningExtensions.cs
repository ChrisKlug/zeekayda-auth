using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering JWT signing key providers with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderSigningExtensions
{
    /// <summary>
    /// Registers a development-only signing key provider that generates an ephemeral RSA key
    /// (≥ 3072 bits) in memory on each startup. The key is never written to disk; tokens issued
    /// in one process lifetime will not validate after a restart.
    /// </summary>
    /// <remarks>
    /// This method is for <strong>local development and testing only</strong>. Startup fails
    /// with <see cref="ZeeKayDaConfigurationException"/> if the host environment is not in
    /// <see cref="DevelopmentSigningOptions.AllowedEnvironments"/>
    /// (defaults to <c>["Development"]</c>, settable via <paramref name="configure"/>). A warning
    /// is always emitted at startup. To persist the key across restarts, use
    /// <see cref="AddPersistedDevelopmentSigning"/> instead.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="DevelopmentSigningOptions"/> (for
    /// example, widening <see cref="DevelopmentSigningOptions.AllowedEnvironments"/>
    /// for an intentional non-Development test host).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered — including by the other
    /// development registration method. Only one signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddInMemoryDevelopmentSigning(
        this ZeeKayDaAuthBuilder builder,
        Action<DevelopmentSigningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        RegisterDevelopmentSigningKeys(builder, persistToDirectory: null, persist: false);

        if (configure is not null)
            builder.Services.AddOptions<DevelopmentSigningOptions>().Configure(configure);

        return builder;
    }

    /// <summary>
    /// Registers a development-only signing key provider that persists an RSA key (≥ 3072 bits)
    /// to a local file so that tokens survive application restarts.
    /// </summary>
    /// <remarks>
    /// This method is for <strong>local development and testing only</strong>. Startup fails
    /// with <see cref="ZeeKayDaConfigurationException"/> if the host environment is not in
    /// <see cref="DevelopmentSigningOptions.AllowedEnvironments"/>
    /// (defaults to <c>["Development"]</c>, settable via <paramref name="configure"/>). A warning
    /// is always emitted at startup. Persisted key files are created with restrictive permissions
    /// (<c>0600</c> on Unix, owner-only ACL on Windows); a key file with broader permissions is
    /// treated as compromised and causes a hard failure at startup. For an ephemeral key with no
    /// persistence, call <see cref="AddInMemoryDevelopmentSigning"/> instead.
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="persistTo">
    /// The directory in which to store the key file. Pass <see langword="null"/> to use
    /// <c>{ContentRootPath}/.zeekayda/signing-keys/</c>.
    /// </param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="DevelopmentSigningOptions"/> (for
    /// example, widening <see cref="DevelopmentSigningOptions.AllowedEnvironments"/>
    /// for an intentional non-Development test host).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered — including by the other
    /// development registration method. Only one signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPersistedDevelopmentSigning(
        this ZeeKayDaAuthBuilder builder,
        string? persistTo = null,
        Action<DevelopmentSigningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        RegisterDevelopmentSigningKeys(builder, persistToDirectory: persistTo, persist: true);

        if (configure is not null)
            builder.Services.AddOptions<DevelopmentSigningOptions>().Configure(configure);

        return builder;
    }

    private static void RegisterDevelopmentSigningKeys(
        ZeeKayDaAuthBuilder builder,
        string? persistToDirectory,
        bool persist)
    {
        // Registered first so a second signing key source is rejected before this method applies
        // any of its own configuration — a caller that catches the rejection must not be left with
        // this call's options callbacks applied to the surviving registration.
        builder.AddSigningKeySource<DevelopmentSigningKeySource>();
        builder.Services.TryAddSingleton<IDevelopmentSigningKeyFileSystem, LocalSigningKeyFileSystem>();

        // Ensures core services are resolvable even if AddZeeKayDaAuth() hasn't run yet.
        builder.Services.AddZeeKayDaAuthCore();

        builder.Services.AddOptions<DevelopmentSigningOptions>()
            .ValidateOnStart();

        // Both are internal, so no caller-supplied configure callback can spoof the environment
        // or give the in-memory registration a directory.
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
            ServiceDescriptor.Singleton<IStartupVerifier, DevelopmentSigningKeyWarningService>());
    }
}
