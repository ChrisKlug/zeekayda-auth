using System.Collections.Concurrent;
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
/// <see cref="ReadAsync"/> parses each file's certificate and checks that the file can sign: the key
/// file's permissions, and its key blocks through <see cref="PemKeyBlocks"/>.
/// A plain key is never parsed or imported at listing; only <see cref="CreateSignerAsync"/> imports one,
/// for the key it is asked for.
/// </para>
/// <para>
/// An encrypted key is decrypted and paired with its certificate at listing, then disposed, because a
/// wrong password should fail before the restart that chooses the key. That happens once per version of
/// the files: the source remembers the hash of the certificate and key text that last decrypted, and
/// skips the decrypt and the password fetch while it is unchanged. A failure is not remembered, so a
/// password fixed at its source is picked up on the next read.
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

    // Keyed by Path: the hash of the certificate and key text whose password last verified.
    private readonly ConcurrentDictionary<string, byte[]> _verifiedVersions = new(StringComparer.Ordinal);

    private const string RsaKeyAlgorithmOid = "1.2.840.113549.1.1.1";

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _options.Value.Algorithm;

    /// <inheritdoc/>
    public async Task<SourceKeyListing> ReadAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;
        var keys = new List<SourceKey>(options.Files.Count);
        var failures = new List<SourceKeyFailure>();

        foreach (var file in options.Files)
        {
            var id = new SourceKeyId(file.Path);
            try
            {
                // A deleted certificate or key file is no longer listed: deleting it revokes the key.
                if (await ListAsync(file, id, cancellationToken).ConfigureAwait(false) is { } key)
                    keys.Add(key);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failures.Add(SigningFileFailure.Of(file.Path, ex));
            }
        }

        return new SourceKeyListing(keys, failures);
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
    /// Parses the certificate of <paramref name="file"/> and checks that the file can sign: any listed
    /// file may be chosen to sign, so one that cannot fails now rather than at the restart that chooses
    /// it. Returns <see langword="null"/> when the certificate or a separate key file does not exist.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The certificate is not valid PEM or its key type is unsupported; a key file is symlinked or too
    /// permissive; the key blocks fail <see cref="PemKeyBlocks.Check"/>; or an encrypted key does not
    /// decrypt and pair.
    /// </exception>
    private async ValueTask<SourceKey?> ListAsync(PemSigningFile file, SourceKeyId id, CancellationToken cancellationToken)
    {
        using var texts = await ReadPemTextsAsync(file, cancellationToken).ConfigureAwait(false);
        if (texts is null)
            return null;

        using var certificate = ParseCertificate(texts.Cert.Span, file.Path);
        PemKeyBlocks.Check(file, texts);
        var key = SourceKey.FromCertificate(certificate, id);

        if (file.PasswordSource is not null)
            await VerifyPasswordOncePerVersionAsync(file, certificate, texts, cancellationToken).ConfigureAwait(false);

        return key;
    }

    /// <summary>
    /// The certificate and key text of <paramref name="file"/>, or <see langword="null"/> when either
    /// file does not exist.
    /// </summary>
    private async ValueTask<PemTexts?> ReadPemTextsAsync(PemSigningFile file, CancellationToken cancellationToken)
    {
        if (file.KeyPath is null)
        {
            return await reader.TryReadPemAsync(file.Path, SigningFileContent.PrivateKey, cancellationToken).ConfigureAwait(false) is { } combined
                ? new(combined, combined)
                : null;
        }

        var certPem = await reader.TryReadPemAsync(file.Path, SigningFileContent.CertificateOnly, cancellationToken).ConfigureAwait(false);
        if (certPem is null)
            return null;

        try
        {
            return await reader.TryReadPemAsync(file.KeyPath, SigningFileContent.PrivateKey, cancellationToken).ConfigureAwait(false) is { } keyPem
                ? new(certPem, keyPem)
                : Disposed(certPem);
        }
        catch
        {
            certPem.Dispose();
            throw;
        }

        static PemTexts? Disposed(PemText certPem)
        {
            certPem.Dispose();
            return null;
        }
    }

    /// <summary>
    /// The certificate and key text of <paramref name="file"/>, read for signing: a missing file throws
    /// rather than unlisting the key.
    /// </summary>
    private async ValueTask<PemTexts> ReadSigningPemTextsAsync(PemSigningFile file, CancellationToken cancellationToken)
    {
        if (file.KeyPath is null)
        {
            var combined = await reader.ReadPemAsync(file.Path, SigningFileContent.PrivateKey, cancellationToken).ConfigureAwait(false);
            return new(combined, combined);
        }

        var certPem = await reader.ReadPemAsync(file.Path, SigningFileContent.CertificateOnly, cancellationToken).ConfigureAwait(false);
        try
        {
            return new(certPem, await reader.ReadPemAsync(file.KeyPath, SigningFileContent.PrivateKey, cancellationToken).ConfigureAwait(false));
        }
        catch
        {
            certPem.Dispose();
            throw;
        }
    }

    private async Task VerifyPasswordOncePerVersionAsync(
        PemSigningFile file, X509Certificate2 certificate, PemTexts texts, CancellationToken cancellationToken)
    {
        var version = VersionOf(file, texts);
        if (_verifiedVersions.TryGetValue(file.Path, out var verified) && verified.AsSpan().SequenceEqual(version))
            return;

        _verifiedVersions.TryRemove(file.Path, out _);
        var password = await ReadPasswordAsync(file, cancellationToken).ConfigureAwait(false);
        using var withKey = WithDecryptedKey(file, certificate, texts.Key.Span, password);
        _verifiedVersions[file.Path] = version;
    }

    // Hashed separately so a byte moving between the two files is still a new version.
    private static byte[] VersionOf(PemSigningFile file, PemTexts texts) =>
        file.KeyPath is null ? texts.Cert.Hash.ToArray() : [.. texts.Cert.Hash, .. texts.Key.Hash];

    /// <summary>
    /// The configured password. An empty one is <c>password_unavailable</c>: it is most often a missing
    /// secret bound to <c>""</c>, and a key encrypted under it is a plain key in disguise.
    /// </summary>
    private static async Task<string> ReadPasswordAsync(PemSigningFile file, CancellationToken cancellationToken)
    {
        var password = await SigningFilePassword.ReadAsync(file.Path, file.PasswordSource!, cancellationToken).ConfigureAwait(false);
        return password.Length > 0
            ? password
            : throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.password_unavailable",
                    $"The password source for '{file.Path}' returned an empty password."));
    }

    private static X509Certificate2 ParseCertificate(ReadOnlySpan<char> certPem, string certificatePath)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = X509Certificate2.CreateFromPem(certPem);
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

        return RefuseRootFirstChain(certificate, certPem, certificatePath);
    }

    /// <summary>
    /// Refuses a chain whose first certificate is a CA. <c>CreateFromPem</c> takes a file's first
    /// <c>CERTIFICATE</c> block, so a chain written root-first would publish the CA's key, then fail to
    /// pair with the private key when it is chosen to sign. A lone certificate is not a chain: a
    /// self-signed one from <c>openssl req -x509</c> is marked as a CA by default.
    /// </summary>
    private static X509Certificate2 RefuseRootFirstChain(X509Certificate2 certificate, ReadOnlySpan<char> certPem, string certificatePath)
    {
        if (certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: true }
            || CertificateCount(certPem) < 2)
            return certificate;

        certificate.Dispose();
        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.file_signing.certificate_is_a_ca",
                $"The first certificate in '{certificatePath}' is a CA certificate. The signing certificate must " +
                "come first in the file, followed by its issuers; reorder the chain leaf-first."));
    }

    private static int CertificateCount(ReadOnlySpan<char> pem)
    {
        var count = 0;
        while (PemEncoding.TryFind(pem, out var fields))
        {
            if (pem[fields.Label].SequenceEqual("CERTIFICATE"))
                count++;

            pem = pem[fields.Location.End.Value..];
        }

        return count;
    }

    /// <summary>
    /// Parses the certificate and private key of <paramref name="file"/>, fetching the password when one
    /// is configured. Used only by <see cref="CreateSignerAsync"/>.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file(s) do not contain a valid PEM-encoded certificate and private key, or the password does
    /// not decrypt the key.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadSigningCertificateAsync(
        PemSigningFile file, CancellationToken cancellationToken)
    {
        // Reads through FileSigningKeyReader and calls X509Certificate2.CreateFromPem rather than
        // X509Certificate2.CreateFromPemFile, which performs its own unvalidated file I/O and would
        // bypass FileSigningKeyReader's permission/symlink validation.
        using var texts = await ReadSigningPemTextsAsync(file, cancellationToken).ConfigureAwait(false);

        // The files may have changed since they were listed.
        PemKeyBlocks.Check(file, texts);

        if (file.PasswordSource is not null)
        {
            var password = await ReadPasswordAsync(file, cancellationToken).ConfigureAwait(false);
            using var certificate = ParseCertificate(texts.Cert.Span, file.Path);
            return WithDecryptedKey(file, certificate, texts.Key.Span, password);
        }

        try
        {
            return RefuseRootFirstChain(X509Certificate2.CreateFromPem(texts.Cert.Span, texts.Key.Span), texts.Cert.Span, file.Path);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            // The exception TYPE is named, never ex.Message — and most sharply here, where the
            // text being parsed is private key material. A failure message is a plain public-API
            // string that neither by-key redaction nor RedactedExceptionWrapper can reach. The root
            // cause travels as the inner exception instead.
            throw InvalidKeyPair(file, ex);
        }
    }

    /// <summary>
    /// A copy of <paramref name="certificate"/> carrying the private key decrypted from
    /// <paramref name="keyPem"/>'s <c>ENCRYPTED PRIVATE KEY</c> block (RFC 5958 §3).
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// <c>key_password_rejected</c> when the key does not decrypt; <c>invalid_pem</c> when it does not
    /// belong to the certificate.
    /// </exception>
    private static X509Certificate2 WithDecryptedKey(
        PemSigningFile file, X509Certificate2 certificate, ReadOnlySpan<char> keyPem, string password)
    {
        // SourceKey.FromCertificate refuses any key type but RSA and EC at listing.
        if (certificate.GetKeyAlgorithm() == RsaKeyAlgorithmOid)
        {
            using var rsa = RSA.Create();
            Decrypt(file, rsa, keyPem, password);
            return Pair(file, () => certificate.CopyWithPrivateKey(rsa));
        }

        using var ecdsa = ECDsa.Create();
        Decrypt(file, ecdsa, keyPem, password);
        return Pair(file, () => certificate.CopyWithPrivateKey(ecdsa));
    }

    private static void Decrypt(PemSigningFile file, AsymmetricAlgorithm key, ReadOnlySpan<char> keyPem, string password)
    {
        try
        {
            key.ImportFromEncryptedPem(keyPem, password);
        }
        catch (CryptographicException ex)
        {
            // Never ex.Message, and never the password: only the exception type is named.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.key_password_rejected",
                    $"The encrypted private key in '{KeyFileOf(file)}' could not be decrypted with the " +
                    $"configured password, or is not a key of the certificate's type: {ex.GetType().FullName} was " +
                    "thrown. Check the password source, and that the key belongs to the certificate. See the " +
                    "inner exception for the root cause."),
                ex);
        }
        catch (ArgumentException ex)
        {
            throw InvalidKeyPair(file, ex);
        }
    }

    private static X509Certificate2 Pair(PemSigningFile file, Func<X509Certificate2> copyWithPrivateKey)
    {
        try
        {
            return copyWithPrivateKey();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw InvalidKeyPair(file, ex);
        }
    }

    private static ZeeKayDaConfigurationException InvalidKeyPair(PemSigningFile file, Exception cause)
    {
        var description = file.KeyPath is null
            ? $"'{file.Path}'"
            : $"certificate '{file.Path}' / private key '{file.KeyPath}'";

        return new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pem",
                $"The file(s) at {description} do not contain a valid PEM-encoded certificate " +
                $"and its private key: {cause.GetType().FullName} was thrown. See the inner exception " +
                "for the root cause."),
            cause);
    }

    private static string KeyFileOf(PemSigningFile file) => file.KeyPath ?? file.Path;
}
