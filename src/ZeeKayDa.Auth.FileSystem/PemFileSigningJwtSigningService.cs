using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more combined cert+key PEM files from the
/// filesystem and signs locally, in process, using each certificate's private-key handle.
/// </summary>
internal sealed class PemFileSigningJwtSigningService : FileSigningJwtSigningService<PemFileSigningOptions>
{
    private readonly FileSigningKeyReader _reader;

    public PemFileSigningJwtSigningService(
        IOptions<PemFileSigningOptions> options,
        TimeProvider timeProvider,
        FileSigningKeyReader reader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(reader);
        _reader = reader;
    }

    /// <inheritdoc/>
    protected override IReadOnlyList<string> GetRegisteredPaths(PemFileSigningOptions options)
    {
        var paths = new List<string>(1 + options.AdditionalPaths.Count) { options.Path };
        paths.AddRange(options.AdditionalPaths);
        return paths;
    }

    /// <inheritdoc/>
    protected override async ValueTask<X509Certificate2> LoadCertificateAsync(
        string path, PemFileSigningOptions options, CancellationToken cancellationToken)
    {
        // A single file carries both the certificate and private-key PEM blocks — per the issue's
        // single-path AddPemFileSigning(string path, ...) shape — so the same text is passed for
        // both the certificate and the key source.
        var pem = await _reader.ReadPemTextAsync(path, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509Certificate2.CreateFromPem(pem, pem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pem",
                $"The file at '{path}' does not contain a valid PEM-encoded certificate and private " +
                $"key: {ex.Message}"));
        }
    }

    /// <inheritdoc/>
    protected override SigningKeyDescriptor BuildKeyDescriptor(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, string path, PemFileSigningOptions options) =>
        SigningKeyDescriptorFactory.BuildDescriptor(
            publicKey,
            keyType,
            options.Algorithm,
            "signing.file_signing.algorithm_key_type_mismatch",
            mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                ? $"PemFileSigningOptions.Algorithm is {options.Algorithm}, but the certificate at " +
                  $"'{path}' is an RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, " +
                  "PS384, or PS512)."
                : $"PemFileSigningOptions.Algorithm is {options.Algorithm}, but the certificate at " +
                  $"'{path}' is an EC certificate. Use an EC algorithm (ES256, ES384, or ES512).");
}
