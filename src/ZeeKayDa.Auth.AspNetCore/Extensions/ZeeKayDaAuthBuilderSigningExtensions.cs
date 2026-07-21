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
    /// <para>
    /// This method is for <strong>local development and testing only</strong>. Startup fails
    /// with <see cref="ZeeKayDaConfigurationException"/> if the host environment is not in
    /// <see cref="DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>
    /// (which defaults to <c>["Development"]</c>, settable via <paramref name="configure"/>).
    /// A warning is always emitted at startup to make the non-production nature of this
    /// configuration explicit.
    /// </para>
    /// <para>
    /// To persist the key so that tokens survive restarts, use
    /// <see cref="AddPersistedDevelopmentJwtSigningKeys"/> instead:
    /// <code>
    /// // Default path ({ContentRootPath}/.zeekayda/signing-keys/):
    /// builder.Services.AddZeeKayDaAuth(…).AddPersistedDevelopmentJwtSigningKeys();
    ///
    /// // Custom path:
    /// builder.Services.AddZeeKayDaAuth(…).AddPersistedDevelopmentJwtSigningKeys(persistTo: "/path/to/keys");
    /// </code>
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="InMemoryDevelopmentSigningKeyOptions"/>
    /// (for example, widening
    /// <see cref="InMemoryDevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>
    /// for an intentional non-Development test host). This type deliberately has no
    /// <c>PersistToDirectory</c> member — see <see cref="InMemoryDevelopmentSigningKeyOptions"/> for why.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered.
    /// Only one signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddInMemoryDevelopmentJwtSigningKeys(
        this ZeeKayDaAuthBuilder builder,
        Action<InMemoryDevelopmentSigningKeyOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        RegisterDevelopmentSigningKeys(builder, persistToDirectory: null, persist: false);

        if (configure is not null)
        {
            // Apply the caller's callback against the smaller public surface type, then copy the
            // result onto the real internal DevelopmentSigningKeyOptions instance. This is what
            // keeps PersistToDirectory unreachable from this method's configure callback while
            // still letting DevelopmentJwtSigningService and friends consume a single
            // IOptions<DevelopmentSigningKeyOptions> regardless of which registration method ran.
            builder.Services.AddOptions<DevelopmentSigningKeyOptions>().Configure(options =>
            {
                var surface = new InMemoryDevelopmentSigningKeyOptions
                {
                    AllowedDevelopmentJwtSigningKeysEnvironments = options.AllowedDevelopmentJwtSigningKeysEnvironments,
                };

                configure(surface);

                options.AllowedDevelopmentJwtSigningKeysEnvironments = surface.AllowedDevelopmentJwtSigningKeysEnvironments;
            });
        }

        return builder;
    }

    /// <summary>
    /// Registers a development-only signing key provider that persists an RSA key (≥ 3072 bits)
    /// to a local file so that tokens survive application restarts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method is for <strong>local development and testing only</strong>. Startup fails
    /// with <see cref="ZeeKayDaConfigurationException"/> if the host environment is not in
    /// <see cref="DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>
    /// (which defaults to <c>["Development"]</c>, settable via <paramref name="configure"/>).
    /// A warning is always emitted at startup to make the non-production nature of this
    /// configuration explicit.
    /// </para>
    /// <para>
    /// Pass <see langword="null"/> as <paramref name="persistTo"/> to use the default path
    /// (<c>{ContentRootPath}/.zeekayda/signing-keys/</c>). Pass an explicit directory path to
    /// use a custom location. Unlike <see cref="AddInMemoryDevelopmentJwtSigningKeys"/>,
    /// <paramref name="persistTo"/> being <see langword="null"/> always means "persist to the
    /// default path" — there is no ephemeral reading of this overload.
    /// </para>
    /// <para>
    /// Persisted key files are created with restrictive permissions (<c>0600</c> on Unix,
    /// owner-only ACL on Windows). A key file with broader permissions is treated as
    /// compromised and causes a hard failure at startup.
    /// </para>
    /// <para>
    /// For an ephemeral in-memory key (no persistence), call
    /// <see cref="AddInMemoryDevelopmentJwtSigningKeys"/> instead.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="persistTo">
    /// The directory in which to store the key file. Pass <see langword="null"/> to use
    /// <c>{ContentRootPath}/.zeekayda/signing-keys/</c>. Pass an explicit path to override.
    /// </param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="DevelopmentSigningKeyOptions"/> (for
    /// example, widening <see cref="DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>
    /// for an intentional non-Development test host).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered.
    /// Only one signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPersistedDevelopmentJwtSigningKeys(
        this ZeeKayDaAuthBuilder builder,
        string? persistTo = null,
        Action<DevelopmentSigningKeyOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        RegisterDevelopmentSigningKeys(builder, persistToDirectory: persistTo, persist: true);

        if (configure is not null)
            builder.Services.AddOptions<DevelopmentSigningKeyOptions>().Configure(configure);

        return builder;
    }

    private static void RegisterDevelopmentSigningKeys(
        ZeeKayDaAuthBuilder builder,
        string? persistToDirectory,
        bool persist)
    {
        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        // Idempotent (TryAdd-based): ensures ISigningKeyRetirementWindowProvider and the open-generic
        // ISanitizingLogger<> — which DevelopmentJwtSigningService's ADR 0015 contract now depends on
        // — are resolvable even if this method is called without AddZeeKayDaAuth() having run first
        // (e.g. a provider-package test that constructs ZeeKayDaAuthBuilder directly). Matches the
        // pattern used by the File/Windows/Azure Key Vault signing-provider packages.
        builder.Services.AddZeeKayDaAuthCore();

        builder.Services.AddOptions<DevelopmentSigningKeyOptions>()
            .ValidateOnStart();

        // Always populate EnvironmentName from the host so the environment gate in
        // DevelopmentJwtSigningService and DevelopmentSigningKeyWarningService can read it
        // without taking a dependency on IHostEnvironment in the core assembly. EnvironmentName's
        // setter is internal (ZeeKayDa.Auth.AspNetCore has InternalsVisibleTo access), so no
        // caller-supplied configure callback (of either public surface type) can ever override or
        // spoof it.
        builder.Services.AddOptions<DevelopmentSigningKeyOptions>().Configure<IHostEnvironment>((options, env) =>
        {
            options.EnvironmentName = env.EnvironmentName;

            if (persist)
            {
                options.PersistToDirectory = persistToDirectory
                    ?? Path.Join(env.ContentRootPath, ".zeekayda", "signing-keys");
            }
            // else: PersistToDirectory stays null → ephemeral mode.
        });

        // AllowedDevelopmentJwtSigningKeysEnvironments lives on DevelopmentSigningKeyOptions (a
        // provider-scoped, code-only opt-in, not a server-wide gate — ADR 0011 §2), so this
        // validator targets that type. Registered here (not in AddZeeKayDaAuth()) because it only
        // makes sense when a development-key registration method is actually in use.
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<DevelopmentSigningKeyOptions>,
                AllowedDevEnvironmentsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<IDevelopmentSigningKeyFileSystem, LocalSigningKeyFileSystem>();
        builder.Services.AddSingleton<IJwtSigningService, DevelopmentJwtSigningService>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, DevelopmentSigningKeyWarningService>());
    }
}
