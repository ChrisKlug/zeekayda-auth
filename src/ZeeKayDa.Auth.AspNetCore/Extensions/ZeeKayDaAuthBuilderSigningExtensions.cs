using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
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
    /// <para>
    /// This method is for <strong>local development and testing only</strong>. Startup fails
    /// with <see cref="ZeeKayDaConfigurationException"/> if the host environment is not in
    /// <see cref="AuthorizationServerOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>.
    /// A warning is always emitted at startup to make the non-production nature of this
    /// configuration explicit.
    /// </para>
    /// <para>
    /// To persist the key so that tokens survive restarts, use the overload that accepts a
    /// <c>persistTo</c> argument:
    /// <code>
    /// // Default path ({ContentRootPath}/.zeekayda/signing-keys/):
    /// builder.Services.AddZeeKayDaAuth(…).AddDevelopmentJwtSigningKeys(persistTo: null);
    ///
    /// // Custom path:
    /// builder.Services.AddZeeKayDaAuth(…).AddDevelopmentJwtSigningKeys(persistTo: "/path/to/keys");
    /// </code>
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered.
    /// Only one signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddDevelopmentJwtSigningKeys(
        this ZeeKayDaAuthBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return RegisterDevelopmentSigningKeys(builder, persistToDirectory: null, persist: false);
    }

    /// <summary>
    /// Registers a development-only signing key provider that persists an RSA key (≥ 3072 bits)
    /// to a local file so that tokens survive application restarts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method is for <strong>local development and testing only</strong>. Startup fails
    /// with <see cref="ZeeKayDaConfigurationException"/> if the host environment is not in
    /// <see cref="AuthorizationServerOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>.
    /// A warning is always emitted at startup to make the non-production nature of this
    /// configuration explicit.
    /// </para>
    /// <para>
    /// Pass <see langword="null"/> as <paramref name="persistTo"/> to use the default path
    /// (<c>{ContentRootPath}/.zeekayda/signing-keys/</c>). Pass an explicit directory path to
    /// use a custom location.
    /// </para>
    /// <para>
    /// Persisted key files are created with restrictive permissions (<c>0600</c> on Unix,
    /// owner-only ACL on Windows). A key file with broader permissions is treated as
    /// compromised and causes a hard failure at startup.
    /// </para>
    /// <para>
    /// For an ephemeral in-memory key (no persistence), call
    /// <see cref="AddDevelopmentJwtSigningKeys(ZeeKayDaAuthBuilder)"/> with no arguments.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="persistTo">
    /// The directory in which to store the key file. Pass <see langword="null"/> to use
    /// <c>{ContentRootPath}/.zeekayda/signing-keys/</c>. Pass an explicit path to override.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered.
    /// Only one signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddDevelopmentJwtSigningKeys(
        this ZeeKayDaAuthBuilder builder,
        string? persistTo)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return RegisterDevelopmentSigningKeys(builder, persistToDirectory: persistTo, persist: true);
    }

    private static ZeeKayDaAuthBuilder RegisterDevelopmentSigningKeys(
        ZeeKayDaAuthBuilder builder,
        string? persistToDirectory,
        bool persist)
    {
        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<DevelopmentSigningKeyOptions>()
            .ValidateOnStart();

        if (persist)
        {
            builder.Services.AddOptions<DevelopmentSigningKeyOptions>()
                .Configure<IHostEnvironment>((options, env) =>
                {
                    options.PersistToDirectory = persistToDirectory
                        ?? Path.Join(env.ContentRootPath, ".zeekayda", "signing-keys");
                });
        }
        // else: PersistToDirectory stays null → ephemeral mode.

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<DevelopmentSigningKeyOptions>,
                DevelopmentSigningKeyOptionsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<IDevelopmentSigningKeyFileSystem, LocalSigningKeyFileSystem>();
        builder.Services.AddSingleton<IJwtSigningService, DevelopmentJwtSigningService>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, DevelopmentSigningKeyWarningService>());

        return builder;
    }
}
