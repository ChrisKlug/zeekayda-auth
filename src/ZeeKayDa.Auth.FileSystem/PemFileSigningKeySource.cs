using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
/// file's permissions, and that its private key block's label matches whether a password is configured.
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

    // RFC 7468 §10 and §11.
    private static readonly HashSet<string> UnencryptedPrivateKeyLabels =
        new(["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"], StringComparer.Ordinal);

    private const string EncryptedPrivateKeyLabel = "ENCRYPTED PRIVATE KEY";

    private const string RsaKeyAlgorithmOid = "1.2.840.113549.1.1.1";

    private enum KeyBlock { None, Plain, Encrypted, LegacyEncrypted }

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
    /// permissive; the key block is missing, in the legacy OpenSSL encrypted format, or encrypted when no
    /// password is configured (or the reverse); or an encrypted key does not decrypt and pair.
    /// </exception>
    private async ValueTask<SourceKey?> ListAsync(PemSigningFile file, SourceKeyId id, CancellationToken cancellationToken)
    {
        if (await ReadPemFilesAsync(file, cancellationToken).ConfigureAwait(false) is not (string certPem, string keyPem))
            return null;

        using var certificate = ParseCertificate(certPem, file.Path);
        CheckKeyBlock(file, keyPem);
        var key = SourceKey.FromCertificate(certificate, id);

        if (file.PasswordSource is not null)
            await VerifyPasswordOncePerVersionAsync(file, certificate, certPem, keyPem, cancellationToken).ConfigureAwait(false);

        return key;
    }

    /// <summary>
    /// The certificate and key text of <paramref name="file"/>, the same text twice for a combined file,
    /// or <see langword="null"/> when either file does not exist.
    /// </summary>
    private async ValueTask<(string CertPem, string KeyPem)?> ReadPemFilesAsync(
        PemSigningFile file, CancellationToken cancellationToken)
    {
        if (await reader.TryReadPemTextAsync(file.Path, cancellationToken).ConfigureAwait(false) is not { } certPem)
            return null;

        if (file.KeyPath is null)
            return (certPem, certPem);

        return await reader.TryReadPemTextAsync(file.KeyPath, cancellationToken).ConfigureAwait(false) is { } keyPem
            ? (certPem, keyPem)
            : null;
    }

    private async Task VerifyPasswordOncePerVersionAsync(
        PemSigningFile file, X509Certificate2 certificate, string certPem, string keyPem, CancellationToken cancellationToken)
    {
        var version = VersionOf(file, certPem, keyPem);
        if (_verifiedVersions.TryGetValue(file.Path, out var verified) && verified.AsSpan().SequenceEqual(version))
            return;

        _verifiedVersions.TryRemove(file.Path, out _);
        var password = await SigningFilePassword.ReadAsync(file.Path, file.PasswordSource!, cancellationToken).ConfigureAwait(false);
        using var withKey = WithDecryptedKey(file, certificate, keyPem, password);
        _verifiedVersions[file.Path] = version;
    }

    // Hashed separately so a byte moving between the two files is still a new version.
    private static byte[] VersionOf(PemSigningFile file, string certPem, string keyPem) =>
        file.KeyPath is null
            ? SHA256.HashData(Encoding.UTF8.GetBytes(certPem))
            : [.. SHA256.HashData(Encoding.UTF8.GetBytes(certPem)), .. SHA256.HashData(Encoding.UTF8.GetBytes(keyPem))];

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
        // Reads through FileSigningKeyReader.ReadPemTextAsync and calls X509Certificate2.CreateFromPem
        // rather than X509Certificate2.CreateFromPemFile, which performs its own unvalidated file I/O
        // and would bypass FileSigningKeyReader's permission/symlink validation.
        var certPem = await reader.ReadPemTextAsync(file.Path, cancellationToken).ConfigureAwait(false);
        var keyPem = file.KeyPath is null
            ? certPem
            : await reader.ReadPemTextAsync(file.KeyPath, cancellationToken).ConfigureAwait(false);

        if (file.PasswordSource is not null)
        {
            var password = await SigningFilePassword.ReadAsync(file.Path, file.PasswordSource, cancellationToken).ConfigureAwait(false);
            using var certificate = ParseCertificate(certPem, file.Path);
            return WithDecryptedKey(file, certificate, keyPem, password);
        }

        try
        {
            return X509Certificate2.CreateFromPem(certPem, keyPem);
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
        PemSigningFile file, X509Certificate2 certificate, string keyPem, string password)
    {
        // Listing has already refused any key type but RSA and EC.
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

    private static void Decrypt(PemSigningFile file, AsymmetricAlgorithm key, string keyPem, string password)
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
                    $"configured password: {ex.GetType().FullName} was thrown. Check the password source, " +
                    "or that the key is not corrupt. See the inner exception for the root cause."),
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

    /// <summary>
    /// Throws unless <paramref name="keyPem"/> holds a private key block in the form
    /// <paramref name="file"/>'s configuration expects: encrypted when a password is configured, plain
    /// otherwise. Only labels are read; the key itself is never parsed.
    /// </summary>
    private static void CheckKeyBlock(PemSigningFile file, ReadOnlySpan<char> keyPem)
    {
        var passwordConfigured = file.PasswordSource is not null;
        switch (FindKeyBlock(keyPem))
        {
            case KeyBlock.None:
                throw NoPrivateKey(file);

            case KeyBlock.LegacyEncrypted:
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.file_signing.legacy_encrypted_key",
                        $"The private key in '{KeyFileOf(file)}' is encrypted in the legacy OpenSSL format " +
                        "(Proc-Type: 4,ENCRYPTED), which cannot be imported. Convert it to an encrypted " +
                        "PKCS#8 key with 'openssl pkcs8 -topk8 -v2 aes-256-cbc'."));

            case KeyBlock.Encrypted when !passwordConfigured:
                throw EncryptionMismatch(file,
                    "is encrypted, but no PasswordSource is configured for it");

            case KeyBlock.Plain when passwordConfigured:
                throw EncryptionMismatch(file,
                    "is not encrypted, but a PasswordSource is configured for it. Remove the password, or " +
                    "encrypt the key with 'openssl pkcs8 -topk8 -v2 aes-256-cbc'");
        }
    }

    /// <summary>
    /// The first complete private key block in <paramref name="pem"/>. The block is located and its
    /// base64 checked, but the key itself is never parsed.
    /// </summary>
    private static KeyBlock FindKeyBlock(ReadOnlySpan<char> pem)
    {
        var rest = pem;
        while (PemEncoding.TryFind(rest, out var fields))
        {
            var label = rest[fields.Label];
            if (label.SequenceEqual(EncryptedPrivateKeyLabel))
                return KeyBlock.Encrypted;

            if (UnencryptedPrivateKeyLabels.Contains(label.ToString()))
                return KeyBlock.Plain;

            rest = rest[fields.Location.End..];
        }

        // RFC 7468 PEM carries no headers, so PemEncoding never matches a legacy block; its header is
        // what identifies it.
        return pem.Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal)
            ? KeyBlock.LegacyEncrypted
            : KeyBlock.None;
    }

    private static string KeyFileOf(PemSigningFile file) => file.KeyPath ?? file.Path;

    private static ZeeKayDaConfigurationException EncryptionMismatch(PemSigningFile file, string problem) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.key_encryption_mismatch",
            $"The private key in '{KeyFileOf(file)}' {problem}."));

    private static ZeeKayDaConfigurationException NoPrivateKey(PemSigningFile file) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.certificate.private_key_not_found",
            file.KeyPath is null
                ? $"The PEM file at '{file.Path}' carries no private key block and names no separate KeyPath. " +
                  "Every listed file must carry its private key, because any of them may be chosen to sign."
                : $"The key file at '{file.KeyPath}' carries no private key block. Every listed file must " +
                  "carry its private key, because any of them may be chosen to sign."));
}
