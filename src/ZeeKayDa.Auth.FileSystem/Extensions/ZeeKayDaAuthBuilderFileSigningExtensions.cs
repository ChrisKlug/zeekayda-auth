using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.FileSystem;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering a filesystem-based (PEM or PFX) JWT signing key provider with
/// <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
/// <remarks>
/// Unlike the Windows Certificate Store provider, neither method here is gated to a specific
/// operating system: PEM/PFX loading in .NET
/// (<see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(ReadOnlySpan{char}, ReadOnlySpan{char})"/>,
/// <see cref="System.Security.Cryptography.X509Certificates.X509CertificateLoader"/>'s <c>LoadPkcs12</c>)
/// is portable BCL functionality with no platform interop — this is the sole recommended signing
/// provider for macOS deployments (ADR 0011 Amendment 7; ADR 0012 Amendments 1/2), and is also the
/// standard fallback for containers, headless CI, and Linux hosts generally.
/// </remarks>
public static class ZeeKayDaAuthBuilderFileSigningExtensions
{
    /// <summary>
    /// Registers a combined cert+key PEM file as the JWT signing key provider. The file identified
    /// by <paramref name="path"/> is loaded at startup and its private key is used for signing
    /// locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The file at <paramref name="path"/> must contain both the certificate and its private key
    /// (RFC 7468 PEM blocks). Filesystem permissions are enforced fail-closed: on Unix the file must
    /// be no more permissive than <c>0600</c>; on Windows its ACL must not grant access to
    /// <c>Everyone</c>, <c>Users</c>, or <c>Authenticated Users</c>. A broader-than-expected
    /// permission is a hard startup failure, not a warning (ADR 0011 §2).
    /// </para>
    /// <para>
    /// Rotation: register additional PEM files via <see cref="PemFileSigningOptions.AddFile"/> in
    /// <paramref name="configure"/>. With exactly one registered file it is the active signer
    /// immediately; with two or more, the file whose certificate <c>NotBefore</c> has arrived and is
    /// most recent is the active signer. See <see cref="SigningKeyRotation"/> and ADR 0011 §3.3/§3.5
    /// for the full rotation/retirement model.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="path">The path to the required/primary combined cert+key PEM file.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="PemFileSigningOptions"/> (for example,
    /// <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/>,
    /// <see cref="PemFileSigningOptions.Algorithm"/>, or additional files for rotation via
    /// <see cref="PemFileSigningOptions.AddFile"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="path"/> is null, empty, or whitespace.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one signing
    /// key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPemFileSigning(
        this ZeeKayDaAuthBuilder builder,
        string path,
        Action<PemFileSigningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        // Defensive/idempotent: guarantees ISigningKeyRetirementWindowProvider is resolvable even
        // when this package is used standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<PemFileSigningOptions>()
            .Configure(options => options.Path = path)
            .Configure(configure ?? (_ => { }))
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PemFileSigningOptions>, PemFileSigningOptionsValidator>());

        AddSharedFileSigningServices(builder);
        builder.Services.AddSingleton<IJwtSigningService, PemFileSigningJwtSigningService>();

        return builder;
    }

    /// <summary>
    /// Registers a PFX/PKCS#12 bundle as the JWT signing key provider. The file identified by
    /// <paramref name="path"/> is loaded at startup and its private key is used for signing locally,
    /// in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Filesystem permissions are enforced fail-closed exactly as for <see cref="AddPemFileSigning"/>.
    /// The PFX password adds a layer of defense in depth on top of filesystem permissions — see
    /// <see cref="PfxFileSigningOptions.PasswordSource"/>'s remarks for why it is an async delegate
    /// rather than a plain <see langword="string"/>.
    /// </para>
    /// <para>
    /// Rotation: register additional PFX files (each with its own password source) via
    /// <see cref="PfxFileSigningOptions.AddFile"/> in <paramref name="configure"/>. See
    /// <see cref="AddPemFileSigning"/>'s remarks for the shared rotation/retirement model.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="path">The path to the required/primary PFX/PKCS#12 file.</param>
    /// <param name="passwordSource">The delegate that supplies <paramref name="path"/>'s password.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="PfxFileSigningOptions"/> (for example,
    /// <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/>,
    /// <see cref="PfxFileSigningOptions.Algorithm"/>, or additional files for rotation via
    /// <see cref="PfxFileSigningOptions.AddFile"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="passwordSource"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="path"/> is null, empty, or whitespace.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one signing
    /// key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPfxFileSigning(
        this ZeeKayDaAuthBuilder builder,
        string path,
        Func<CancellationToken, ValueTask<string>> passwordSource,
        Action<PfxFileSigningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(passwordSource);

        builder.Services.AddZeeKayDaAuthCore();

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<PfxFileSigningOptions>()
            .Configure(options =>
            {
                options.Path = path;
                options.PasswordSource = passwordSource;
            })
            .Configure(configure ?? (_ => { }))
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PfxFileSigningOptions>, PfxFileSigningOptionsValidator>());

        AddSharedFileSigningServices(builder);
        builder.Services.AddSingleton<IJwtSigningService, PfxFileSigningJwtSigningService>();

        return builder;
    }

    private static void AddSharedFileSigningServices(ZeeKayDaAuthBuilder builder)
    {
        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<FileSigningKeyReader>();
        builder.Services.AddHostedService<FileSigningStartupService>();
    }
}
