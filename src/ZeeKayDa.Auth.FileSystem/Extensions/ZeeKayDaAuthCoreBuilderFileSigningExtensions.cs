using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.FileSystem;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering a filesystem-based (PEM or PFX) JWT signing key provider with
/// <see cref="ZeeKayDaAuthCoreBuilder"/>.
/// </summary>
/// <remarks>
/// Unlike the Windows Certificate Store provider, neither method here is gated to a specific
/// operating system — PEM/PFX loading is portable BCL functionality with no platform interop.
/// This is the recommended provider for macOS, containers, headless CI, and Linux generally.
/// </remarks>
public static class ZeeKayDaAuthCoreBuilderFileSigningExtensions
{
    /// <summary>
    /// Registers a single PEM certificate as the JWT signing key. The
    /// file(s) identified by <paramref name="path"/> and <paramref name="keyPath"/> are read once at
    /// startup and the private key is used for signing locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <paramref name="keyPath"/> is <see langword="null"/> (the default), <paramref name="path"/>
    /// must contain both the certificate and its private key (RFC 7468 PEM blocks). When
    /// <paramref name="keyPath"/> is supplied, <paramref name="path"/> is certificate-only and
    /// <paramref name="keyPath"/> holds the private key — the convention used by Let's
    /// Encrypt/certbot (<c>fullchain.pem</c> + <c>privkey.pem</c>) and cert-manager.
    /// </para>
    /// <para>
    /// Filesystem permissions are enforced fail-closed on every loaded file, including
    /// <paramref name="keyPath"/>: no more permissive than <c>0600</c> on Unix, and on Windows no
    /// ACL access for <c>Everyone</c>, <c>Users</c>, or <c>Authenticated Users</c>. A
    /// broader-than-expected permission is a hard startup failure, not a warning.
    /// </para>
    /// <para>
    /// To rotate, use the
    /// <see cref="AddPemFileSigning{TBuilder}(TBuilder,SigningAlgorithm,Action{PemFileSigningOptions})"/>
    /// overload and list both files.
    /// </para>
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="path">
    /// The path to the PEM file that signs — a combined cert+key file when
    /// <paramref name="keyPath"/> is <see langword="null"/>, otherwise the certificate-only file.
    /// </param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="keyPath">
    /// The path to a separate private-key-only PEM file for <paramref name="path"/>, or
    /// <see langword="null"/> (the default) when <paramref name="path"/> is a combined cert+key
    /// file.
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
    /// Thrown when a signing key source has already been registered. Only one signing key provider
    /// is allowed.
    /// </exception>
    public static TBuilder AddPemFileSigning<TBuilder>(
        this TBuilder builder,
        string path,
        SigningAlgorithm algorithm,
        string? keyPath = null)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (keyPath is not null)
            ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        return AddPemFileSigning(builder, algorithm, options => options.Files.Add(new PemSigningFile(path, keyPath)));
    }

    /// <summary>
    /// Registers the PEM certificates listed in <see cref="PemFileSigningOptions.Files"/> as the JWT
    /// signing keys. They are read at startup; the framework decides from their validity windows
    /// which one signs, locally, in process, and which are published.
    /// </summary>
    /// <remarks>
    /// <para>
    /// At least one file is required, and every one must carry its private key. Startup fails when
    /// no file is listed, when two entries name the same file, or when no listed certificate is valid.
    /// </para>
    /// <para>
    /// Filesystem permissions are enforced fail-closed on every loaded file, exactly as for
    /// <see cref="AddPemFileSigning{TBuilder}(TBuilder,string,SigningAlgorithm,string)"/>.
    /// </para>
    /// <para>
    /// Rotation: add the successor's file and restart. It is published at once and signs once it has
    /// been published for the lead time; the file it replaces can be removed once it is no longer
    /// published. See <see cref="PemFileSigningOptions.Files"/> for how a certificate's dates count.
    /// </para>
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="algorithm">The JWS algorithm every listed file is signed under.</param>
    /// <param name="configure">A callback that lists the signing key files.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered. Only one signing key provider
    /// is allowed.
    /// </exception>
    public static TBuilder AddPemFileSigning<TBuilder>(
        this TBuilder builder,
        SigningAlgorithm algorithm,
        Action<PemFileSigningOptions> configure)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.AddSigningKeySource<PemFileSigningKeySource>();

        builder.Services.AddZeeKayDaOptions<PemFileSigningOptions>()
            .Configure(options => options.Algorithm = algorithm)
            .Configure(configure);

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PemFileSigningOptions>, PemFileSigningOptionsValidator>());

        AddSharedFileSigningServices(builder);

        return builder;
    }

    /// <summary>
    /// Registers a single PFX/PKCS#12 bundle as the JWT signing key. The
    /// file identified by <paramref name="path"/> is read once at startup and its private key is used
    /// for signing locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Filesystem permissions are enforced fail-closed exactly as for
    /// <see cref="AddPemFileSigning{TBuilder}(TBuilder,string,SigningAlgorithm,string)"/>. The PFX
    /// password adds defense in depth on top of that — see
    /// <see cref="PfxFile.PasswordSource"/> for why it is an async delegate rather than a
    /// plain <see langword="string"/>.
    /// </para>
    /// <para>
    /// To rotate, use the
    /// <see cref="AddPfxFileSigning{TBuilder}(TBuilder,SigningAlgorithm,Action{PfxFileSigningOptions})"/>
    /// overload and list both bundles.
    /// </para>
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="path">The path to the PFX/PKCS#12 file that signs.</param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="passwordSource">The delegate that supplies <paramref name="path"/>'s password.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="passwordSource"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="path"/> is null, empty, or whitespace.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered. Only one signing key provider
    /// is allowed.
    /// </exception>
    public static TBuilder AddPfxFileSigning<TBuilder>(
        this TBuilder builder,
        string path,
        SigningAlgorithm algorithm,
        Func<CancellationToken, Task<string>> passwordSource)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(passwordSource);

        return AddPfxFileSigning(builder, algorithm, options => options.Files.Add(new PfxFile(path, passwordSource)));
    }

    /// <summary>
    /// Registers the PFX/PKCS#12 bundles listed in <see cref="PfxFileSigningOptions.Files"/> as the
    /// JWT signing keys. They are read at startup; the framework decides from their validity windows
    /// which one signs, locally, in process, and which are published.
    /// </summary>
    /// <remarks>
    /// <para>
    /// At least one bundle is required, every one must carry its private key, and every one needs its
    /// own password source, since real-world bundles are frequently password-per-file. Startup fails
    /// when no bundle is listed, when two entries name the same file, when a bundle carries no private
    /// key, or when no listed certificate is valid.
    /// </para>
    /// <para>
    /// Listing reads each certificate out of its bundle without decrypting the key bag; only the
    /// bundle chosen to sign has its private key imported.
    /// </para>
    /// <para>
    /// Rotation: add the successor's bundle and restart. It is published at once and signs once it
    /// has been published for the lead time; the bundle it replaces can be removed once it is no
    /// longer published. See <see cref="PfxFileSigningOptions.Files"/> for how a certificate's dates
    /// count.
    /// </para>
    /// </remarks>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="algorithm">The JWS algorithm every listed bundle is signed under.</param>
    /// <param name="configure">A callback that lists the signing key bundles.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered. Only one signing key provider
    /// is allowed.
    /// </exception>
    public static TBuilder AddPfxFileSigning<TBuilder>(
        this TBuilder builder,
        SigningAlgorithm algorithm,
        Action<PfxFileSigningOptions> configure)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.AddSigningKeySource<PfxFileSigningKeySource>();

        builder.Services.AddZeeKayDaOptions<PfxFileSigningOptions>()
            .Configure(options => options.Algorithm = algorithm)
            .Configure(configure);

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PfxFileSigningOptions>, PfxFileSigningOptionsValidator>());

        AddSharedFileSigningServices(builder);

        return builder;
    }

    private static void AddSharedFileSigningServices(ZeeKayDaAuthCoreBuilder builder)
    {
        builder.Services.TryAddSingleton<FileSigningKeyReader>();
    }
}
