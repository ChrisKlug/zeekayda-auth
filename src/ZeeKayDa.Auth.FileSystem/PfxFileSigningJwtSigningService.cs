using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more PFX/PKCS#12 bundles from the filesystem
/// and signs locally, in process, using each certificate's private-key handle.
/// </summary>
internal sealed class PfxFileSigningJwtSigningService : FileSigningJwtSigningService<PfxFileSigningOptions>
{
    private readonly FileSigningKeyReader _reader;

    public PfxFileSigningJwtSigningService(
        IOptions<PfxFileSigningOptions> options,
        TimeProvider timeProvider,
        FileSigningKeyReader reader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(reader);
        _reader = reader;
    }

    /// <inheritdoc/>
    protected override IReadOnlyList<string> GetRegisteredPaths(PfxFileSigningOptions options)
    {
        var paths = new List<string>(1 + options.AdditionalFiles.Count) { options.Path };
        paths.AddRange(options.AdditionalFiles.Select(file => file.Path));
        return paths;
    }

    /// <inheritdoc/>
    protected override async ValueTask<X509Certificate2> LoadCertificateAsync(
        string path, PfxFileSigningOptions options, CancellationToken cancellationToken)
    {
        var passwordSource = ResolvePasswordSource(path, options);
        var bytes = await _reader.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var password = await passwordSource(cancellationToken).ConfigureAwait(false);

        try
        {
            return X509CertificateLoader.LoadPkcs12(bytes, password);
        }
        catch (CryptographicException ex)
        {
            // ex.Message comes from the BCL PKCS#12 parser and never echoes the supplied password —
            // still, the message is not further embellished with any secret-derived detail here.
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pfx",
                $"The PFX/PKCS#12 file at '{path}' could not be loaded: {ex.Message}. Verify the file " +
                "is a valid PKCS#12 bundle and that the configured password is correct."));
        }
    }

    /// <inheritdoc/>
    protected override SigningKeyDescriptor BuildKeyDescriptor(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, string path, PfxFileSigningOptions options) =>
        SigningKeyDescriptorFactory.BuildDescriptor(
            publicKey,
            keyType,
            options.Algorithm,
            "signing.file_signing.algorithm_key_type_mismatch",
            mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                ? $"PfxFileSigningOptions.Algorithm is {options.Algorithm}, but the certificate at " +
                  $"'{path}' is an RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, " +
                  "PS384, or PS512)."
                : $"PfxFileSigningOptions.Algorithm is {options.Algorithm}, but the certificate at " +
                  $"'{path}' is an EC certificate. Use an EC algorithm (ES256, ES384, or ES512).");

    private static Func<CancellationToken, ValueTask<string>> ResolvePasswordSource(string path, PfxFileSigningOptions options)
    {
        if (string.Equals(path, options.Path, StringComparison.Ordinal))
            return options.PasswordSource!;

        var match = options.AdditionalFiles.FirstOrDefault(file => string.Equals(file.Path, path, StringComparison.Ordinal));
        return match.PasswordSource
            ?? throw new InvalidOperationException($"No password source is registered for path '{path}'.");
    }
}
