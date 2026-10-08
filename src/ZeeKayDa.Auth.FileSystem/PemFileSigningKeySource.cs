using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// An <see cref="ISigningKeySource"/> that lists the PEM certificates in
/// <see cref="PemFileSigningOptions.Files"/> and signs locally, in process, with whichever of them
/// the framework chooses.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ReadAsync"/> parses only each file's certificate — no private key is parsed or imported —
/// but checks that every file can sign: a separate key file's permissions, or a combined file's private
/// key block. Only <see cref="CreateSignerAsync"/> imports a private key, for the key it is asked for.
/// </para>
/// <para>
/// This source performs no algorithm/key-type check of its own.
/// <see cref="SigningKeySetBuilder"/> validates every reported key, keyed on the source id — which
/// here is the configured file path, so its failures still name the offending file.
/// </para>
/// </remarks>
internal sealed class PemFileSigningKeySource(
    IOptions<PemFileSigningOptions> options,
    FileSigningKeyReader reader) : ISigningKeySource
{
    private readonly IOptions<PemFileSigningOptions> _options = options;

    // The key blocks X509Certificate2.CreateFromPem can import. An ENCRYPTED PRIVATE KEY block is not
    // one of them, so a combined file carrying only that cannot sign.
    private static readonly HashSet<string> UnencryptedPrivateKeyLabels =
        new(["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"], StringComparer.Ordinal);

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _options.Value.Algorithm;

    /// <inheritdoc/>
    public async Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;
        var keys = new List<SourceKey>(options.Files.Count);

        foreach (var file in options.Files)
        {
            // A deleted certificate file is no longer listed: deleting it revokes the key.
            using var certificate = await LoadPublicCertificateAsync(file, cancellationToken).ConfigureAwait(false);
            if (certificate is not null)
                keys.Add(SourceKey.FromCertificate(certificate, new SourceKeyId(file.Path)));
        }

        return keys;
    }

    /// <inheritdoc/>
    public async Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        var options = _options.Value;
        var file = options.Files.FirstOrDefault(f => string.Equals(f.Path, id.Value, StringComparison.Ordinal))
            ?? throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not a listed PEM file.");

        using var certificate = await LoadSigningCertificateAsync(file, cancellationToken).ConfigureAwait(false);
        return LocalSigner.FromCertificate(certificate, options.Algorithm);
    }

    /// <summary>
    /// Parses only the certificate of <paramref name="file"/>, and checks that the file can sign
    /// without parsing or importing its private key: any listed file may be chosen to sign, so one
    /// that cannot fails now rather than at the restart that chooses it. Returns <see langword="null"/>
    /// when the certificate file, or a separate key file, does not exist.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file does not contain a valid PEM-encoded certificate; a combined file carries no private
    /// key block; or a separate key file is symlinked or too permissive.
    /// </exception>
    private async ValueTask<X509Certificate2?> LoadPublicCertificateAsync(
        PemSigningFile file, CancellationToken cancellationToken)
    {
        var certificatePath = file.Path;
        if (await reader.TryReadPemTextAsync(certificatePath, cancellationToken).ConfigureAwait(false) is not { } certPem)
            return null;

        // A separate key file is held to the permission and symlink rules without being read, and a
        // deleted one unlists the key like a deleted certificate; a combined file must at least carry a
        // private key block. Every listed key is published, so this matters whether or not it signs today.
        if (file.KeyPath is not null && !reader.TryValidate(file.KeyPath))
            return null;

        // Judged before the certificate is parsed, so nothing after the parse can throw past it; the
        // parse error is still reported first.
        var hasNoKey = file.KeyPath is null && !HasUnencryptedPrivateKeyBlock(certPem);
        var certificate = ParseCertificate(certPem, certificatePath);
        if (hasNoKey)
        {
            certificate.Dispose();
            throw NoPrivateKey(certificatePath);
        }

        return certificate;
    }

    private static X509Certificate2 ParseCertificate(string certPem, string certificatePath)
    {
        try
        {
            return X509Certificate2.CreateFromPem(certPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            // The exception TYPE is named, never ex.Message. A PEM parse error is raised over the
            // file's own content, and a failure message is a plain public-API string that neither
            // by-key redaction nor RedactedExceptionWrapper can reach. The root cause travels as
            // the inner exception instead.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.invalid_pem",
                    $"The file at '{certificatePath}' does not contain a valid PEM-encoded " +
                    $"certificate: {ex.GetType().FullName} was thrown. See the inner exception for " +
                    "the root cause."),
                ex);
        }
    }

    /// <summary>
    /// Parses the certificate and private key of <paramref name="file"/>. Used only by
    /// <see cref="CreateSignerAsync"/>.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file(s) do not contain a valid PEM-encoded certificate and private key.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadSigningCertificateAsync(
        PemSigningFile file, CancellationToken cancellationToken)
    {
        // Reads through FileSigningKeyReader.ReadPemTextAsync and calls X509Certificate2.CreateFromPem
        // rather than X509Certificate2.CreateFromPemFile, which performs its own unvalidated file I/O
        // and would bypass FileSigningKeyReader's permission/symlink validation.
        var certPem = await reader.ReadPemTextAsync(file.Path, cancellationToken).ConfigureAwait(false);

        // With no separate key path, the combined file carries both PEM blocks, so the same text is
        // passed for both the certificate and the key source.
        var keyPem = file.KeyPath is null
            ? certPem
            : await reader.ReadPemTextAsync(file.KeyPath, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509Certificate2.CreateFromPem(certPem, keyPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            var description = file.KeyPath is null
                ? $"'{file.Path}'"
                : $"certificate '{file.Path}' / private key '{file.KeyPath}'";

            // The exception TYPE is named, never ex.Message — and most sharply here, where the
            // text being parsed is private key material. A failure message is a plain public-API
            // string that neither by-key redaction nor RedactedExceptionWrapper can reach. The root
            // cause travels as the inner exception instead.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.invalid_pem",
                    $"The file(s) at {description} do not contain a valid PEM-encoded certificate " +
                    $"and private key: {ex.GetType().FullName} was thrown. See the inner exception " +
                    "for the root cause."),
                ex);
        }
    }

    /// <summary>
    /// Whether <paramref name="pem"/> holds a complete, well-formed private key block of a kind
    /// <see cref="X509Certificate2.CreateFromPem(ReadOnlySpan{char}, ReadOnlySpan{char})"/> can import.
    /// The block is located and its base64 checked, but the key itself is never parsed.
    /// </summary>
    private static bool HasUnencryptedPrivateKeyBlock(ReadOnlySpan<char> pem)
    {
        while (PemEncoding.TryFind(pem, out var fields))
        {
            if (UnencryptedPrivateKeyLabels.Contains(pem[fields.Label].ToString()))
                return true;

            pem = pem[fields.Location.End..];
        }

        return false;
    }

    private static ZeeKayDaConfigurationException NoPrivateKey(string path) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.certificate.private_key_not_found",
            $"The PEM file at '{path}' carries no private key block and names no separate KeyPath. Every " +
            "listed file must carry its private key, because any of them may be chosen to sign."));
}
