using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.MacOS;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering the macOS Keychain as a JWT signing key provider with
/// <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderMacOsKeychainSigningExtensions
{
    /// <summary>
    /// Registers the macOS Keychain as the JWT signing key provider. The item identified by
    /// <paramref name="label"/> is loaded from the Keychain at startup and used for signing locally,
    /// in process, via a native <c>SecKeyRef</c> handle.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a macOS-only provider — see Apple's Security.framework. Calling this method on a
    /// non-macOS runtime throws <see cref="PlatformNotSupportedException"/>.
    /// </para>
    /// <para>
    /// <paramref name="label"/>'s shape — certificate-backed, or a bare, certificate-less key — is
    /// auto-detected at load time from what actually exists in the Keychain: a certificate anchors on
    /// its own <c>NotBefore</c>/<c>NotAfter</c>; a bare key has no explicit activation (valid only
    /// while it remains the sole registered key — the single-key bootstrap exemption).
    /// </para>
    /// <para>
    /// Rotation: register additional labels via <see cref="MacOsKeychainSigningOptions.AddKey(string)"/>
    /// (shape auto-detected, same as <paramref name="label"/>) or
    /// <see cref="MacOsKeychainSigningOptions.AddKey(string, DateTimeOffset, DateTimeOffset?)"/> (a
    /// bare key with an explicit activation window) in <paramref name="configure"/>. With exactly one
    /// registered item it is the active signer immediately; with two or more, the item whose
    /// activation has arrived and is most recent is the active signer. See
    /// <see cref="SigningKeyRotation"/> and ADR 0011 §3.3/§3.5 for the full rotation/retirement model.
    /// </para>
    /// <para>
    /// Adding, removing, or updating an item registered with this method requires a host restart — the
    /// Keychain is read at startup and on each <see cref="JwtSigningServiceOptions.RefreshInterval"/>
    /// tick thereafter, but the set of registered labels itself is fixed at process start.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="label">The label of the required/primary Keychain item to sign with.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="MacOsKeychainSigningOptions"/> (for
    /// example, <see cref="JwtSigningServiceOptions.RefreshInterval"/>,
    /// <see cref="MacOsKeychainSigningOptions.Algorithm"/>, or additional keys for rotation via
    /// <see cref="MacOsKeychainSigningOptions.AddKey(string)"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="PlatformNotSupportedException">Thrown when called on a non-macOS runtime.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="label"/> is null, empty, or whitespace.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one signing
    /// key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddMacOsKeychainSigning(
        this ZeeKayDaAuthBuilder builder,
        string label,
        Action<MacOsKeychainSigningOptions>? configure = null)
    {
        // Platform gate first, before any argument validation: no argument combination makes this
        // method valid on a non-macOS OS, so this check must win over ArgumentNullException.
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException(
                "AddMacOsKeychainSigning requires macOS. The macOS Keychain (Security.framework) is " +
                "not available as a production signing key store on this operating system.");
        }

        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(label);

        // Defensive/idempotent: guarantees ISigningKeyRetirementWindowProvider and
        // IOptions<AuthorizationServerOptions> are resolvable even when this package is used
        // standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<MacOsKeychainSigningOptions>()
            .Configure(options => options.Label = label)
            .Configure(configure ?? (_ => { }))
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<MacOsKeychainSigningOptions>, MacOsKeychainSigningOptionsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<IKeychainItemReader, KeychainItemReader>();
        builder.Services.AddSingleton<IJwtSigningService, MacOsKeychainSigningJwtSigningService>();
        builder.Services.AddHostedService<MacOsKeychainSigningStartupService>();

        return builder;
    }
}
