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
    protected override IReadOnlyList<RegisteredSigningFile> GetRegisteredFiles(PemFileSigningOptions options)
    {
        var files = new List<RegisteredSigningFile>(1 + options.AdditionalFiles.Count)
        {
            ToRegisteredFile(options.Path, options.KeyPath),
        };
        files.AddRange(options.AdditionalFiles.Select(file => ToRegisteredFile(file.Path, file.KeyPath)));
        return files;
    }

    /// <inheritdoc/>
    protected override async ValueTask<X509Certificate2> LoadCertificateAsync(
        RegisteredSigningFile file, PemFileSigningOptions options, CancellationToken cancellationToken)
    {
        // Deliberately still reads both the certificate and key text through
        // FileSigningKeyReader.ReadPemTextAsync (one validated, single-open read per file) and calls
        // X509Certificate2.CreateFromPem(certPem, keyPem), rather than X509Certificate2.CreateFromPemFile
        // (which takes a path and performs its own, unvalidated file I/O). CreateFromPemFile would
        // bypass FileSigningKeyReader's permission/symlink validation and TOCTOU-closing discipline
        // (see that type's remarks) for both the combined and split cases — a regression this
        // provider's whole security model exists to prevent. CreateFromPem accepts the certificate
        // and key as independent PEM text, so it supports the split-file case exactly as well as
        // CreateFromPemFile would, without reopening either file outside the validated read path.
        var keyPath = file.AdditionalPaths.Count > 0 ? file.AdditionalPaths[0] : null;

        var certPem = await _reader.ReadPemTextAsync(file.Id, cancellationToken).ConfigureAwait(false);
        // With no separate key path, the combined file carries both PEM blocks, so the same text is
        // passed for both the certificate and the key source — byte-for-byte the same call this
        // provider has always made.
        var keyPem = keyPath is null
            ? certPem
            : await _reader.ReadPemTextAsync(keyPath, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509Certificate2.CreateFromPem(certPem, keyPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            var description = keyPath is null
                ? $"'{file.Id}'"
                : $"certificate '{file.Id}' / private key '{keyPath}'";

            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pem",
                $"The file(s) at {description} do not contain a valid PEM-encoded certificate and " +
                $"private key: {ex.Message}"));
        }
    }

    private static RegisteredSigningFile ToRegisteredFile(string path, string? keyPath) =>
        new(path, keyPath is null ? null : [keyPath]);

    /// <inheritdoc/>
    protected override SigningAlgorithm GetAlgorithm(PemFileSigningOptions options) => options.Algorithm;
}
