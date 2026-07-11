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
    /// Registers the Windows Certificate Store as the JWT signing key provider. The certificate
    /// identified by <paramref name="thumbprint"/> is loaded from the given store at startup and
    /// its private key is used for signing locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a Windows-only provider — see <see cref="System.Security.Cryptography.X509Certificates.X509Store"/>.
    /// Calling this method on a non-Windows runtime throws <see cref="PlatformNotSupportedException"/>.
    /// </para>
    /// <para>
    /// Rotation: register additional certificates from the same <paramref name="storeLocation"/>/
    /// <paramref name="storeName"/> via <see cref="WindowsCertificateStoreSigningOptions.AddCertificate"/>
    /// in <paramref name="configure"/>. With exactly one registered certificate it is the active
    /// signer immediately; with two or more, the certificate whose <c>NotBefore</c> has arrived and
    /// is most recent is the active signer. See <see cref="SigningKeyRotation"/> and
    /// ADR 0011 §3.3/§3.5 for the full rotation/retirement model.
    /// </para>
    /// <para>
    /// Adding, removing, or updating a certificate registered with this method requires a host
    /// restart — the store is read at startup and on each <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/>
    /// tick thereafter, but the set of registered thumbprints itself is fixed at process start.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="thumbprint">The thumbprint of the required/primary certificate to sign with.</param>
    /// <param name="storeLocation">The store location to search.</param>
    /// <param name="storeName">The store name to search.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="WindowsCertificateStoreSigningOptions"/>
    /// (for example, <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/>,
    /// <see cref="WindowsCertificateStoreSigningOptions.Algorithm"/>, or additional certificates for
    /// rotation via <see cref="WindowsCertificateStoreSigningOptions.AddCertificate"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when called on a non-Windows runtime.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="thumbprint"/> is null, empty, or whitespace.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one
    /// signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddWindowsCertificateStoreSigning(
        this ZeeKayDaAuthBuilder builder,
        string thumbprint,
        StoreLocation storeLocation,
        StoreName storeName,
        Action<WindowsCertificateStoreSigningOptions>? configure = null)
    {
        // Platform gate first, before any argument validation: no argument combination makes this
        // method valid on a non-Windows OS, so this check must win over ArgumentNullException.
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "AddWindowsCertificateStoreSigning requires Windows. The Windows Certificate Store " +
                "(System.Security.Cryptography.X509Certificates.X509Store) is not available as a " +
                "production signing key store on this operating system.");
        }

        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);

        // Defensive/idempotent: guarantees ISigningKeyRetirementWindowProvider and
        // IOptions<AuthorizationServerOptions> are resolvable even when this package is used
        // standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<WindowsCertificateStoreSigningOptions>()
            .Configure(options =>
            {
                options.Thumbprint = ThumbprintFormat.Normalize(thumbprint);
                options.StoreLocation = storeLocation;
                options.StoreName = storeName;
            })
            .Configure(configure ?? (_ => { }))
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<WindowsCertificateStoreSigningOptions>,
                WindowsCertificateStoreSigningOptionsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<ICertificateStoreReader, CertificateStoreReader>();
        builder.Services.AddSingleton<IJwtSigningService, WindowsCertificateStoreSigningJwtSigningService>();
        builder.Services.AddHostedService<WindowsCertificateStoreSigningStartupService>();

        return builder;
    }
}
