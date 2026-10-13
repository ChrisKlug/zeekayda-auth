using System.Formats.Asn1;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Judges the private key blocks of a <see cref="PemSigningFile"/> by their labels, headers and, for an
/// encrypted key, its encryption parameters. No key is ever decrypted or parsed here.
/// </summary>
internal static class PemKeyBlocks
{
    // RFC 7468 §10 and §11.
    private static readonly HashSet<string> UnencryptedLabels =
        new(["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"], StringComparer.Ordinal);

    private const string EncryptedLabel = "ENCRYPTED PRIVATE KEY";

    // RFC 8018 §4.2 asks for at least 1000; 2048 is OpenSSL's default.
    private const int MinimumIterations = 2048;

    private const string Pbes2Oid = "1.2.840.113549.1.5.13";
    private const string Pbkdf2Oid = "1.2.840.113549.1.5.12";

    private static readonly HashSet<string> AesCbcOids =
        new(["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42"], StringComparer.Ordinal);

    private const string Reencrypt = "openssl pkcs8 -topk8 -v2 aes-256-cbc";

    /// <summary>
    /// Throws unless <paramref name="file"/>'s key is in the form its configuration expects: encrypted
    /// under strong parameters when a password is configured, plain otherwise, with no unencrypted or
    /// legacy-encrypted copy anywhere in either file.
    /// </summary>
    /// <param name="file">The configured file.</param>
    /// <param name="certPem">The certificate file's text; the same as <paramref name="keyPem"/> for a combined file.</param>
    /// <param name="keyPem">The text of the file that carries the key.</param>
    public static void Check(PemSigningFile file, string certPem, string keyPem)
    {
        var keyFile = file.KeyPath ?? file.Path;
        if (IsLegacyEncrypted(keyPem))
            throw LegacyEncrypted(keyFile);

        if (file.KeyPath is not null && IsLegacyEncrypted(certPem))
            throw LegacyEncrypted(file.Path);

        var (plain, encrypted) = Scan(keyPem);
        if (!plain && encrypted.IsEmpty)
            throw NoPrivateKey(file);

        if (file.PasswordSource is null)
        {
            if (!plain)
                throw Mismatch($"The private key in '{keyFile}' is encrypted, but no PasswordSource is configured for it.");

            return;
        }

        if (plain)
            throw PlainBesidePassword(keyFile);

        if (file.KeyPath is not null && Scan(certPem).Plain)
            throw PlainBesidePassword(file.Path);

        CheckEncryptionParameters(keyFile, encrypted);
    }

    /// <summary>
    /// Whether <paramref name="pem"/> carries an unencrypted key block, and the base64 of its first
    /// <c>ENCRYPTED PRIVATE KEY</c> block. Blocks are located and their base64 checked, never decoded.
    /// </summary>
    private static (bool Plain, ReadOnlyMemory<char> Encrypted) Scan(string pem)
    {
        var plain = false;
        var encrypted = ReadOnlyMemory<char>.Empty;
        var offset = 0;
        while (PemEncoding.TryFind(pem.AsSpan(offset), out var fields))
        {
            var label = pem.AsSpan(offset)[fields.Label];
            if (UnencryptedLabels.Contains(label.ToString()))
                plain = true;
            else if (encrypted.IsEmpty && label.SequenceEqual(EncryptedLabel))
                encrypted = pem.AsMemory(offset)[fields.Base64Data];

            offset += fields.Location.End.Value;
        }

        return (plain, encrypted);
    }

    // RFC 7468 PEM carries no headers, so PemEncoding never matches a legacy block; its header is what
    // identifies it.
    private static bool IsLegacyEncrypted(string pem) =>
        pem.Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal);

    /// <summary>
    /// Refuses an <c>EncryptedPrivateKeyInfo</c> (RFC 5958 §3) unless it is PBES2 (RFC 8018 §6.2) with
    /// PBKDF2 at <see cref="MinimumIterations"/> or more and AES-CBC. PBES1, DES, 3DES and RC2 are legacy
    /// (RFC 8018 §6.1, Appendix B.2) and brute-forceable offline, which is the exposure the password is for.
    /// </summary>
    private static void CheckEncryptionParameters(string keyFile, ReadOnlyMemory<char> base64)
    {
        // Only the encryption parameters are read: the ciphertext is never decrypted here.
        var der = Convert.FromBase64String(base64.ToString());
        try
        {
            var algorithm = new AsnReader(der, AsnEncodingRules.BER).ReadSequence().ReadSequence();
            if (algorithm.ReadObjectIdentifier() != Pbes2Oid)
                throw Weak(keyFile, "a PBES1 scheme");

            var pbes2 = algorithm.ReadSequence();
            var kdf = pbes2.ReadSequence();
            if (kdf.ReadObjectIdentifier() != Pbkdf2Oid)
                throw Weak(keyFile, "a key derivation function other than PBKDF2");

            var kdfParameters = kdf.ReadSequence();
            kdfParameters.ReadEncodedValue();
            if (!kdfParameters.TryReadInt32(out var iterations) || iterations < MinimumIterations)
                throw Weak(keyFile, $"fewer than {MinimumIterations} PBKDF2 iterations");

            if (!AesCbcOids.Contains(pbes2.ReadSequence().ReadObjectIdentifier()))
                throw Weak(keyFile, "a cipher other than AES-CBC");
        }
        catch (AsnContentException ex)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.invalid_pem",
                    $"The encrypted private key in '{keyFile}' is not a valid EncryptedPrivateKeyInfo: " +
                    $"{ex.GetType().FullName} was thrown. See the inner exception for the root cause."),
                ex);
        }
    }

    private static ZeeKayDaConfigurationException Weak(string keyFile, string what) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.weak_key_encryption",
            $"The private key in '{keyFile}' is encrypted with {what}. Only PBES2 with PBKDF2 at " +
            $"{MinimumIterations} or more iterations and AES-CBC is accepted; re-encrypt it with '{Reencrypt}'."));

    private static ZeeKayDaConfigurationException LegacyEncrypted(string path) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.legacy_encrypted_key",
            $"The file '{path}' carries a private key encrypted in the legacy OpenSSL format " +
            $"(Proc-Type: 4,ENCRYPTED), which cannot be imported. Convert it to an encrypted PKCS#8 key " +
            $"with '{Reencrypt}', and remove the legacy copy."));

    private static ZeeKayDaConfigurationException PlainBesidePassword(string path) =>
        Mismatch($"The file '{path}' carries an unencrypted private key while a PasswordSource is configured, " +
            $"so the password protects nothing. Remove the unencrypted key, or encrypt it with '{Reencrypt}'.");

    private static ZeeKayDaConfigurationException Mismatch(string message) =>
        new(new ZeeKayDaConfigurationFailure("signing.file_signing.key_encryption_mismatch", message));

    private static ZeeKayDaConfigurationException NoPrivateKey(PemSigningFile file) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.certificate.private_key_not_found",
            file.KeyPath is null
                ? $"The PEM file at '{file.Path}' carries no private key block and names no separate KeyPath. " +
                  "Every listed file must carry its private key, because any of them may be chosen to sign."
                : $"The key file at '{file.KeyPath}' carries no private key block. Every listed file must " +
                  "carry its private key, because any of them may be chosen to sign."));
}
