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
/// operating system — PEM/PFX loading is portable BCL functionality with no platform interop.
/// This is the recommended provider for macOS, containers, headless CI, and Linux generally.
/// </remarks>
public static class ZeeKayDaAuthBuilderFileSigningExtensions
{
    /// <summary>
    /// Registers a single PEM certificate as the JWT signing key, with no rotation staged. The
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
    /// To stage a rotation, use the
    /// <see cref="AddPemFileSigning(ZeeKayDaAuthBuilder,SigningAlgorithm,Action{PemFileSigningOptions})"/>
    /// overload and fill the <c>Previous</c>/<c>Current</c>/<c>Next</c> slots. This overload takes no
    /// configuration callback precisely so that the file it names is unambiguously the one that
    /// signs.
    /// </para>
    /// </remarks>
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
    public static ZeeKayDaAuthBuilder AddPemFileSigning(
        this ZeeKayDaAuthBuilder builder,
        string path,
        SigningAlgorithm algorithm,
        string? keyPath = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (keyPath is not null)
            ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        return AddPemFileSigning(builder, algorithm, options => options.Current = new PemSigningFile(path, keyPath));
    }

    /// <summary>
    /// Registers PEM certificates as the JWT signing keys, configured into the
    /// <see cref="PemFileSigningOptions.Previous"/>, <see cref="PemFileSigningOptions.Current"/> and
    /// <see cref="PemFileSigningOptions.Next"/> slots. Every configured slot is read once at startup
    /// and published; only <c>Current</c>'s private key is ever read, and it signs locally, in
    /// process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PemFileSigningOptions.Current"/> is required; <c>Previous</c> and <c>Next</c> are
    /// independently optional. Startup fails when no <c>Current</c> is configured, when two slots
    /// name the same file, or when <c>Current</c>'s certificate is expired or not valid yet.
    /// </para>
    /// <para>
    /// Filesystem permissions are enforced fail-closed on every loaded file, exactly as for
    /// <see cref="AddPemFileSigning(ZeeKayDaAuthBuilder,string,SigningAlgorithm,string)"/>.
    /// </para>
    /// <para>
    /// Rotation: stage the successor as <c>Next</c> so its public half is published ahead of time,
    /// then promote it to <c>Current</c> and demote the key it succeeds to <c>Previous</c>. The slots
    /// are read once at startup, so each move takes effect on restart. How long a successor must sit
    /// in <c>Next</c> before promotion is the operator's decision — see
    /// <see cref="PemFileSigningOptions.Next"/>.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="algorithm">The JWS algorithm every configured slot is signed under.</param>
    /// <param name="configure">A callback that fills the signing key slots.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered. Only one signing key provider
    /// is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPemFileSigning(
        this ZeeKayDaAuthBuilder builder,
        SigningAlgorithm algorithm,
        Action<PemFileSigningOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // Transitional, removed with IJwtSigningService itself in #511. The Azure Key Vault providers
        // are not ported to a signing key source yet, so AddZeeKayDaSigningKeySource below cannot see
        // their registrations. Without this, registering
        // one of them and then this one would leave the application with two signing providers rather
        // than the one it is allowed. The reverse order is not detectable from here and is deferred
        // until those ports land.
        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.Services.AddZeeKayDaSigningKeySource<PemFileSigningKeySource>();

        // Defensive/idempotent: guarantees the core services are resolvable even when this package is
        // used standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.Services.AddOptions<PemFileSigningOptions>()
            .Configure(options => options.Algorithm = algorithm)
            .Configure(configure)
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PemFileSigningOptions>, PemFileSigningOptionsValidator>());

        AddSharedFileSigningServices(builder);

        return builder;
    }

    /// <summary>
    /// Registers a single PFX/PKCS#12 bundle as the JWT signing key, with no rotation staged. The
    /// file identified by <paramref name="path"/> is read once at startup and its private key is used
    /// for signing locally, in process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Filesystem permissions are enforced fail-closed exactly as for
    /// <see cref="AddPemFileSigning(ZeeKayDaAuthBuilder,string,SigningAlgorithm,string)"/>. The PFX
    /// password adds defense in depth on top of that — see
    /// <see cref="PfxFile.PasswordSource"/> for why it is an async delegate rather than a
    /// plain <see langword="string"/>.
    /// </para>
    /// <para>
    /// To stage a rotation, use the
    /// <see cref="AddPfxFileSigning(ZeeKayDaAuthBuilder,SigningAlgorithm,Action{PfxFileSigningOptions})"/>
    /// overload and fill the <c>Previous</c>/<c>Current</c>/<c>Next</c> slots. This overload takes no
    /// configuration callback precisely so that the bundle it names is unambiguously the one that
    /// signs.
    /// </para>
    /// </remarks>
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
    public static ZeeKayDaAuthBuilder AddPfxFileSigning(
        this ZeeKayDaAuthBuilder builder,
        string path,
        SigningAlgorithm algorithm,
        Func<CancellationToken, ValueTask<string>> passwordSource)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(passwordSource);

        return AddPfxFileSigning(builder, algorithm, options => options.Current = new PfxFile(path, passwordSource));
    }

    /// <summary>
    /// Registers PFX/PKCS#12 bundles as the JWT signing keys, configured into the
    /// <see cref="PfxFileSigningOptions.Previous"/>, <see cref="PfxFileSigningOptions.Current"/> and
    /// <see cref="PfxFileSigningOptions.Next"/> slots. Every configured slot is read once at startup
    /// and published; only <c>Current</c>'s private key is ever decrypted, and it signs locally, in
    /// process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PfxFileSigningOptions.Current"/> is required; <c>Previous</c> and <c>Next</c> are
    /// independently optional. Every slot needs its own password source — a published-only bundle's
    /// certificate sits inside a password-protected safe — and real-world bundles are frequently
    /// password-per-file. Startup fails when no <c>Current</c> is configured, when two slots name the
    /// same file, or when <c>Current</c>'s certificate is expired or not valid yet.
    /// </para>
    /// <para>
    /// A published-only slot's private key is never decrypted: its certificate is read out of the
    /// bundle without touching the key bag. See <see cref="PfxFileSigningOptions"/>.
    /// </para>
    /// <para>
    /// Rotation: stage the successor as <c>Next</c> so its public half is published ahead of time,
    /// then promote it to <c>Current</c> and demote the key it succeeds to <c>Previous</c>. The slots
    /// are read once at startup, so each move takes effect on restart. How long a successor must sit
    /// in <c>Next</c> before promotion is the operator's decision — see
    /// <see cref="PfxFileSigningOptions.Next"/>.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="algorithm">The JWS algorithm every configured slot is signed under.</param>
    /// <param name="configure">A callback that fills the signing key slots.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key source has already been registered. Only one signing key provider
    /// is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddPfxFileSigning(
        this ZeeKayDaAuthBuilder builder,
        SigningAlgorithm algorithm,
        Action<PfxFileSigningOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // Transitional, removed with IJwtSigningService itself in #511. The Azure Key Vault providers
        // are not ported to a signing key source yet, so AddZeeKayDaSigningKeySource below cannot see
        // their registrations. Without this, registering
        // one of them and then this one would leave the application with two signing providers rather
        // than the one it is allowed. The reverse order is not detectable from here and is deferred
        // until those ports land.
        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.Services.AddZeeKayDaSigningKeySource<PfxFileSigningKeySource>();

        // Defensive/idempotent: guarantees the core services are resolvable even when this package is
        // used standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.Services.AddOptions<PfxFileSigningOptions>()
            .Configure(options => options.Algorithm = algorithm)
            .Configure(configure)
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PfxFileSigningOptions>, PfxFileSigningOptionsValidator>());

        AddSharedFileSigningServices(builder);

        return builder;
    }

    private static void AddSharedFileSigningServices(ZeeKayDaAuthBuilder builder)
    {
        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<FileSigningKeyReader>();
    }
}
