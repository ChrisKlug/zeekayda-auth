using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering the Windows Certificate Store as a JWT signing key provider
/// with <see cref="ZeeKayDaAuthCoreBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthCoreBuilderWindowsCertificateStoreSigningExtensions
{
    /// <summary>
    /// Registers a single certificate from a Windows Certificate Store as the JWT signing key. The
    /// certificate <paramref name="certificate"/> finds is read at startup and every
    /// <see cref="SigningKeyOptions.RefreshInterval"/>, and its private key is used for signing
    /// locally, in process.
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
    /// To rotate, use the
    /// <see cref="AddWindowsCertificateStoreSigning{TBuilder}(TBuilder,SigningAlgorithm,StoreLocation,StoreName,Action{WindowsCertificateStoreSigningOptions})"/>
    /// overload and list both certificates.
    /// </para>
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
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
    public static TBuilder AddWindowsCertificateStoreSigning<TBuilder>(
        this TBuilder builder,
        CertificateLookup certificate,
        SigningAlgorithm algorithm,
        StoreLocation storeLocation,
        StoreName storeName)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        // Platform gate first, before any argument validation: no argument combination makes this
        // method valid on a non-Windows OS, so this check must win over ArgumentNullException.
        ThrowIfNotWindows();

        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(certificate);

        return AddWindowsCertificateStoreSigning(
            builder, algorithm, storeLocation, storeName, options => options.Certificates.Add(certificate));
    }

    /// <summary>
    /// Registers the certificates listed in <see cref="WindowsCertificateStoreSigningOptions.Certificates"/>
    /// from a Windows Certificate Store as the JWT signing keys. They are read at startup; the
    /// framework decides from their validity windows which one signs, locally, in process, and which
    /// are published.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a Windows-only provider. Calling this method on a non-Windows runtime throws
    /// <see cref="PlatformNotSupportedException"/>.
    /// </para>
    /// <para>
    /// At least one certificate is required, and every one must have a private key this process can
    /// use. Startup fails when none is listed, when one is listed twice, or when no listed
    /// certificate is valid. Every certificate is looked up in the one
    /// <paramref name="storeLocation"/>/<paramref name="storeName"/> given here.
    /// </para>
    /// <para>
    /// Rotation: add the successor and restart. It is published at once and signs once it has been
    /// published for the lead time; the certificate it replaces can be removed once it is no longer
    /// published. See <see cref="WindowsCertificateStoreSigningOptions.Certificates"/> for how a
    /// certificate's dates count.
    /// </para>
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="algorithm">The JWS algorithm every listed certificate is signed under.</param>
    /// <param name="storeLocation">The store location every certificate is looked up in.</param>
    /// <param name="storeName">The store name every certificate is looked up in.</param>
    /// <param name="configure">A callback that lists the signing certificates.</param>
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
    public static TBuilder AddWindowsCertificateStoreSigning<TBuilder>(
        this TBuilder builder,
        SigningAlgorithm algorithm,
        StoreLocation storeLocation,
        StoreName storeName,
        Action<WindowsCertificateStoreSigningOptions> configure)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ThrowIfNotWindows();

        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.AddSigningKeySource<WindowsCertificateStoreSigningKeySource>();

        builder.Services.AddZeeKayDaOptions<WindowsCertificateStoreSigningOptions>()
            .Configure(options =>
            {
                options.Algorithm = algorithm;
                options.StoreLocation = storeLocation;
                options.StoreName = storeName;
            })
            .Configure(configure);

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
