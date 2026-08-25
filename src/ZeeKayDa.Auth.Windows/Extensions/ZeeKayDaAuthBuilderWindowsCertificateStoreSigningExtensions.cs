using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering the Windows Certificate Store as a JWT signing key provider
/// with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderWindowsCertificateStoreSigningExtensions
{
    /// <summary>
    /// Registers a single certificate from a Windows Certificate Store as the JWT signing key, with
    /// no rotation staged. The certificate <paramref name="certificate"/> finds is read once at
    /// startup and its private key is used for signing locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a Windows-only provider. Calling this method on a non-Windows runtime throws
    /// <see cref="PlatformNotSupportedException"/>.
    /// </para>
    /// <para>
    /// The store is read exactly once, at startup. Adding, removing, or replacing a configured
    /// certificate has no effect until the host restarts.
    /// </para>
    /// <para>
    /// To stage a rotation, use the
    /// <see cref="AddWindowsCertificateStoreSigning(ZeeKayDaAuthBuilder,SigningAlgorithm,StoreLocation,StoreName,Action{WindowsCertificateStoreSigningOptions})"/>
    /// overload and fill the <c>Previous</c>/<c>Current</c>/<c>Next</c> slots. This overload takes no
    /// configuration callback precisely so that the certificate it names is unambiguously the one
    /// that signs.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="certificate">Finds the certificate that signs.</param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="storeLocation">The store location to search.</param>
    /// <param name="storeName">The store name to search.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when called on a non-Windows runtime.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="certificate"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key provider has already been registered. Only one is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddWindowsCertificateStoreSigning(
        this ZeeKayDaAuthBuilder builder,
        CertificateLookup certificate,
        SigningAlgorithm algorithm,
        StoreLocation storeLocation,
        StoreName storeName)
    {
        // Platform gate first, before any argument validation: no argument combination makes this
        // method valid on a non-Windows OS, so this check must win over ArgumentNullException.
        ThrowIfNotWindows();

        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(certificate);

        return AddWindowsCertificateStoreSigning(
            builder, algorithm, storeLocation, storeName, options => options.Current = certificate);
    }

    /// <summary>
    /// Registers certificates from a Windows Certificate Store as the JWT signing keys, configured
    /// into the <see cref="WindowsCertificateStoreSigningOptions.Previous"/>,
    /// <see cref="WindowsCertificateStoreSigningOptions.Current"/> and
    /// <see cref="WindowsCertificateStoreSigningOptions.Next"/> slots. Every configured slot is read
    /// once at startup and published; only <c>Current</c>'s private key is ever opened, and it signs
    /// locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a Windows-only provider. Calling this method on a non-Windows runtime throws
    /// <see cref="PlatformNotSupportedException"/>.
    /// </para>
    /// <para>
    /// <see cref="WindowsCertificateStoreSigningOptions.Current"/> is required; <c>Previous</c> and
    /// <c>Next</c> are independently optional. Startup fails when no <c>Current</c> is configured,
    /// when two slots name the same certificate, or when <c>Current</c>'s certificate is expired or
    /// not valid yet.
    /// </para>
    /// <para>
    /// Every slot is looked up in the one <paramref name="storeLocation"/>/<paramref name="storeName"/>
    /// given here, and the store is read exactly once, at startup.
    /// </para>
    /// <para>
    /// Rotation: stage the successor as <c>Next</c> so its public half is published ahead of time,
    /// then promote it to <c>Current</c> and demote the certificate it succeeds to <c>Previous</c>.
    /// Each move takes effect on restart. How long a successor must sit in <c>Next</c> before
    /// promotion is the operator's decision — see
    /// <see cref="WindowsCertificateStoreSigningOptions.Next"/>.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="algorithm">The JWS algorithm every configured slot is signed under.</param>
    /// <param name="storeLocation">The store location every slot is looked up in.</param>
    /// <param name="storeName">The store name every slot is looked up in.</param>
    /// <param name="configure">A callback that fills the signing key slots.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when called on a non-Windows runtime.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key provider has already been registered. Only one is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddWindowsCertificateStoreSigning(
        this ZeeKayDaAuthBuilder builder,
        SigningAlgorithm algorithm,
        StoreLocation storeLocation,
        StoreName storeName,
        Action<WindowsCertificateStoreSigningOptions> configure)
    {
        ThrowIfNotWindows();

        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // Transitional, removed with IJwtSigningService itself in #511: the sibling PFX provider has
        // not been ported to a signing key source yet, so AddZeeKayDaSigningKeySource below cannot
        // see its registration. Without this, registering both would leave the application with two
        // signing providers rather than the one it is allowed.
        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.Services.AddZeeKayDaSigningKeySource<WindowsCertificateStoreSigningKeySource>();

        // Defensive/idempotent: guarantees the core services are resolvable even when this package is
        // used standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.Services.AddOptions<WindowsCertificateStoreSigningOptions>()
            .Configure(options =>
            {
                options.Algorithm = algorithm;
                options.StoreLocation = storeLocation;
                options.StoreName = storeName;
            })
            .Configure(configure)
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<WindowsCertificateStoreSigningOptions>,
                WindowsCertificateStoreSigningOptionsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<ICertificateStoreReader, CertificateStoreReader>();
        builder.Services.TryAddSingleton<ICertificateKeyExtractor, CertificateKeyExtractor>();

        return builder;
    }

    private static void ThrowIfNotWindows()
    {
        if (OperatingSystem.IsWindows())
            return;

        throw new PlatformNotSupportedException(
            "AddWindowsCertificateStoreSigning requires Windows. The Windows Certificate Store " +
            "(System.Security.Cryptography.X509Certificates.X509Store) is not available as a " +
            "production signing key store on this operating system.");
    }
}
