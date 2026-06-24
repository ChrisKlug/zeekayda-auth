using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
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
    /// Registers a development-only signing key provider that generates an RSA key (≥ 3072 bits)
    /// in memory on each startup, with optional persistence to a local file so that tokens
    /// survive application restarts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method is for <strong>local development and testing only</strong>. Outside a
    /// Development environment, startup fails with <see cref="ZeeKayDaConfigurationException"/>
    /// unless <see cref="AuthorizationServerOptions.AllowDevelopmentJwtSigningKeysOutsideDevelopment"/>
    /// is set to <see langword="true"/>. A warning is always emitted at startup to make the
    /// non-production nature of this configuration explicit.
    /// </para>
    /// <para>
    /// Call with no arguments for an ephemeral key (default):
    /// <code>
    /// builder.Services.AddZeeKayDaAuth(…).AddDevelopmentJwtSigningKeys();
    /// </code>
    /// Ephemeral keys are never written to disk. Tokens issued in one process lifetime will
    /// not validate after a restart.
    /// </para>
    /// <para>
    /// Pass <see langword="null"/> as <paramref name="persistTo"/> to opt into persistence at
    /// the default path (<c>{ContentRootPath}/.zeekayda/signing-keys/</c>):
    /// <code>
    /// builder.Services.AddZeeKayDaAuth(…).AddDevelopmentJwtSigningKeys(persistTo: null);
    /// </code>
    /// Or supply an explicit path:
    /// <code>
    /// builder.Services.AddZeeKayDaAuth(…).AddDevelopmentJwtSigningKeys(persistTo: "/path/to/keys");
    /// </code>
    /// </para>
    /// <para>
    /// Persisted key files are created with restrictive permissions (<c>0600</c> on Unix,
    /// owner-only ACL on Windows). A key file with broader permissions is treated as
    /// compromised and causes a hard failure at startup.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="persistTo">
    /// When omitted (default), an ephemeral in-memory key is used. Pass
    /// <see langword="null"/> to persist to the default path
    /// (<c>{ContentRootPath}/.zeekayda/signing-keys/</c>). Pass an explicit directory path to
    /// persist to a custom location.
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
        string? persistTo = DevelopmentSigningKeyRegistration.NoPath)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<DevelopmentSigningKeyOptions>();

        if (persistTo != DevelopmentSigningKeyRegistration.NoPath)
        {
            // persistTo was explicitly passed (either null = default path, or a custom path).
            builder.Services.AddOptions<DevelopmentSigningKeyOptions>()
                .Configure<Microsoft.Extensions.Hosting.IHostEnvironment>((options, env) =>
                {
                    options.PersistToDirectory = persistTo
                        ?? Path.Combine(env.ContentRootPath, ".zeekayda", "signing-keys");
                });
        }
        // else: no argument passed → PersistToDirectory stays null → ephemeral mode.

        builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.AddSingleton<IJwtSigningService, DevelopmentJwtSigningService>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, DevelopmentSigningKeyWarningService>());

        return builder;
    }
}

/// <summary>
/// Sentinel used to distinguish "argument not passed" from "argument passed as null"
/// in <see cref="ZeeKayDaAuthBuilderSigningExtensions.AddDevelopmentJwtSigningKeys"/>.
/// </summary>
internal static class DevelopmentSigningKeyRegistration
{
    /// <summary>
    /// Sentinel string used as the default value for the <c>persistTo</c> parameter.
    /// Its identity — not value — is what matters; it is never used as an actual path.
    /// </summary>
    internal const string NoPath = "\0ephemeral\0";
}
