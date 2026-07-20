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
    /// Registers a PEM certificate (and, optionally, a separate private-key PEM file) as the JWT
    /// signing key provider. The file(s) identified by <paramref name="path"/> and
    /// <paramref name="keyPath"/> are loaded at startup and the private key is used for signing
    /// locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <paramref name="keyPath"/> is <see langword="null"/> (the default), <paramref name="path"/>
    /// must contain both the certificate and its private key (RFC 7468 PEM blocks) — a single
    /// combined cert+key file. When <paramref name="keyPath"/> is supplied, <paramref name="path"/>
    /// is a certificate-only file and <paramref name="keyPath"/> is a separate private-key-only
    /// file — the convention used by Let's Encrypt/certbot (<c>fullchain.pem</c> + <c>privkey.pem</c>),
    /// cert-manager in Kubernetes, and most corporate PKI tooling (issue #405).
    /// </para>
    /// <para>
    /// Filesystem permissions are enforced fail-closed on every file actually loaded: on Unix the
    /// file must be no more permissive than <c>0600</c>; on Windows its ACL must not grant access to
    /// <c>Everyone</c>, <c>Users</c>, or <c>Authenticated Users</c>. A broader-than-expected
    /// permission is a hard startup failure, not a warning (ADR 0011 §2). This applies equally to
    /// <paramref name="keyPath"/> when supplied, since it is the file that actually carries the
    /// sensitive private key material.
    /// </para>
    /// <para>
    /// Rotation: register additional PEM files (combined or split) via
    /// <see cref="PemFileSigningOptions.AddFile(string, string)"/> in <paramref name="configure"/>.
    /// With exactly one registered file it is the active signer immediately; with two or more, the
    /// file whose certificate <c>NotBefore</c> has arrived and is most recent is the active signer.
    /// See <see cref="SigningKeyRotation"/> and ADR 0011 §3.3/§3.5 for the full rotation/retirement
    /// model.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="path">
    /// The path to the required/primary PEM file — a combined cert+key file when
    /// <paramref name="keyPath"/> is <see langword="null"/>, otherwise the certificate-only file.
    /// </param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="keyPath">
    /// The path to a separate private-key-only PEM file for <paramref name="path"/>, or
    /// <see langword="null"/> (the default) when <paramref name="path"/> is a combined cert+key
    /// file.
    /// </param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="PemFileSigningOptions"/> (for example,
    /// <see cref="ZeeKayDa.Auth.Tokens.RotatingKeySourceOptions.KeyRotationCheckInterval"/> or additional files for
    /// rotation via <see cref="PemFileSigningOptions.AddFile(string, string)"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="path"/> is null, empty, or whitespace, or when
    /// <paramref name="keyPath"/> is empty or whitespace (but not <see langword="null"/>).
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one signing
    /// key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPemFileSigning(
        this ZeeKayDaAuthBuilder builder,
        string path,
        SigningAlgorithm algorithm,
        string? keyPath = null,
        Action<PemFileSigningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (keyPath is not null)
            ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        // Defensive/idempotent: guarantees ISigningKeyRetirementWindowProvider is resolvable even
        // when this package is used standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<PemFileSigningOptions>()
            .Configure(options =>
            {
                options.Path = path;
                options.KeyPath = keyPath;
                options.Algorithm = algorithm;
            })
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
    /// Filesystem permissions are enforced fail-closed exactly as for <see cref="AddPemFileSigning(ZeeKayDaAuthBuilder,string,SigningAlgorithm,string,Action{PemFileSigningOptions})"/>.
    /// The PFX password adds a layer of defense in depth on top of filesystem permissions — see
    /// <see cref="PfxFileSigningOptions.PasswordSource"/>'s remarks for why it is an async delegate
    /// rather than a plain <see langword="string"/>.
    /// </para>
    /// <para>
    /// Rotation: register additional PFX files (each with its own password source) via
    /// <see cref="PfxFileSigningOptions.AddFile"/> in <paramref name="configure"/>. See
    /// <see cref="AddPemFileSigning(ZeeKayDaAuthBuilder,string,SigningAlgorithm,string,Action{PemFileSigningOptions})"/>'s remarks for the shared rotation/retirement model.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="path">The path to the required/primary PFX/PKCS#12 file.</param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="passwordSource">The delegate that supplies <paramref name="path"/>'s password.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="PfxFileSigningOptions"/> (for example,
    /// <see cref="ZeeKayDa.Auth.Tokens.RotatingKeySourceOptions.KeyRotationCheckInterval"/> or additional files for
    /// rotation via <see cref="PfxFileSigningOptions.AddFile"/>).
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
        SigningAlgorithm algorithm,
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
                options.Algorithm = algorithm;
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
