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
/// Runs on every operating system; the recommended provider for macOS, Linux and containers.
/// </remarks>
public static class ZeeKayDaAuthCoreBuilderFileSigningExtensions
{
    /// <summary>
    /// Registers a single PEM certificate as the JWT signing key. The
    /// file(s) identified by <paramref name="path"/> and <paramref name="keyPath"/> are read at startup
    /// and every <see cref="SigningKeyOptions.RefreshInterval"/>, and the private key is used for
    /// signing locally, in process.
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
    /// Filesystem permissions are enforced fail-closed on every file that carries the private key:
    /// no more permissive than <c>0600</c> on Unix, and on Windows no ACL access for <c>Everyone</c>,
    /// <c>Users</c>, or <c>Authenticated Users</c>. A certificate-only <paramref name="path"/> may be
    /// readable by anyone, as certbot writes <c>fullchain.pem</c>, but it must carry no private key and
    /// only a trusted owner may replace it: on Unix it is owned by root or the process's user and not
    /// writable by group or other users; on Windows no broad principal may write, delete, change the
    /// permissions of, or take ownership of it. A broader-than-expected permission is a hard failure,
    /// not a warning.
    /// </para>
    /// <para>
    /// No file may be reached through a symlink. certbot's <c>live/</c> directory is made of symlinks
    /// into <c>archive/</c>, so copy the files out with a certbot deploy hook rather than pointing at
    /// <c>live/</c> directly.
    /// </para>
    /// <para>
    /// A PKCS#8-encrypted key takes <paramref name="passwordSource"/>, which adds defense in depth on
    /// top of the permissions — see <see cref="PemSigningFile.PasswordSource"/> for when it is invoked
    /// and what it protects against.
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
    /// <param name="passwordSource">
    /// Supplies the password of an encrypted private key, or <see langword="null"/> (the default) when
    /// the key is not encrypted.
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
        string? keyPath = null,
        Func<CancellationToken, Task<string>>? passwordSource = null)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (keyPath is not null)
            ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        return AddPemFileSigning(builder, algorithm, options => options.Files.Add(new PemSigningFile(path, keyPath, passwordSource)));
    }

    /// <summary>
    /// Registers the PEM certificates listed in <see cref="PemFileSigningOptions.Files"/> as the JWT
    /// signing keys. They are read at startup and every <see cref="SigningKeyOptions.RefreshInterval"/>;
    /// the framework decides from their validity windows which one signs, locally, in process, and
    /// which are published.
    /// </summary>
    /// <remarks>
    /// <para>
    /// At least one file is required, and every one must carry its private key. Startup fails when
    /// no file is listed, when two entries name the same file, or when no listed certificate is valid.
    /// </para>
    /// <para>
    /// Filesystem permissions are enforced fail-closed on every loaded file, exactly as for
    /// <see cref="AddPemFileSigning{TBuilder}(TBuilder,string,SigningAlgorithm,string,Func{CancellationToken,Task{string}})"/>.
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

        // First, so a rejected second source leaves none of this call's options applied.
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
    /// file identified by <paramref name="path"/> is read at startup and every
    /// <see cref="SigningKeyOptions.RefreshInterval"/>, and its private key is used for signing
    /// locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Filesystem permissions are enforced fail-closed exactly as for
    /// <see cref="AddPemFileSigning{TBuilder}(TBuilder,string,SigningAlgorithm,string,Func{CancellationToken,Task{string}})"/>. The PFX
    /// password adds defense in depth on top of that — see
    /// <see cref="PfxFile.PasswordSource"/> for why it is an async delegate rather than a
    /// plain <see langword="string"/>.
    /// </para>
    /// <para>
    /// To rotate, use the
    /// <see cref="AddPfxFileSigning{TBuilder}(TBuilder,SigningAlgorithm,Action{PfxFileSigningOptions})"/>
    /// overload and list both bundles.
    /// </para>
    /// <para>
    /// A private key shrouded under weaker parameters than PBES2 with AES-CBC and PBKDF2 at 2048 or more
    /// iterations, such as a default Windows export's 3DES and SHA-1, or not shrouded at all, still signs, and logs a
    /// <c>signing.file_signing.weak_key_encryption</c> warning once per version of the file.
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
    /// JWT signing keys. They are read at startup and every <see cref="SigningKeyOptions.RefreshInterval"/>;
    /// the framework decides from their validity windows which one signs, locally, in process, and
    /// which are published.
    /// </summary>
    /// <remarks>
    /// <para>
    /// At least one bundle is required, every one must carry its private key, and every one needs its
    /// own password source, since real-world bundles are frequently password-per-file. Startup fails
    /// when no bundle is listed, when two entries name the same file, when a bundle carries no private
    /// key, or when no listed certificate is valid.
    /// </para>
    /// <para>
    /// A private key shrouded under weaker parameters than PBES2 with AES-CBC and PBKDF2 at 2048 or more
    /// iterations, such as a default Windows export's 3DES and SHA-1, or not shrouded at all, still signs, and logs a
    /// <c>signing.file_signing.weak_key_encryption</c> warning once per version of the file.
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

        // First, so a rejected second source leaves none of this call's options applied.
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
