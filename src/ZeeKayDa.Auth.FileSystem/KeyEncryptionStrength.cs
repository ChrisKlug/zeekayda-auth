using System.Formats.Asn1;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Judges how an <c>EncryptedPrivateKeyInfo</c> (RFC 5958 §3) is encrypted, from its parameters alone:
/// the ciphertext is never decrypted. PEM refuses a weak key; PFX warns.
/// </summary>
internal static class KeyEncryptionStrength
{
    // RFC 8018 §4.2 asks for at least 1000; 2048 is OpenSSL's default.
    public const int MinimumIterations = 2048;

    private const string Pbes2Oid = "1.2.840.113549.1.5.13";
    private const string Pbkdf2Oid = "1.2.840.113549.1.5.12";

    private static readonly HashSet<string> AesCbcOids =
        new(["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42"], StringComparer.Ordinal);

    /// <summary>
    /// What makes the encryption weak, or <see langword="null"/> when it is PBES2 (RFC 8018 §6.2) with
    /// PBKDF2 at <see cref="MinimumIterations"/> or more and AES-CBC. PBES1, the PKCS#12 PBE schemes, DES,
    /// 3DES and RC2 are legacy (RFC 8018 §6.1, Appendix B.2) and brute-forceable offline, which is the
    /// exposure the password is for.
    /// </summary>
    /// <exception cref="AsnContentException">The bytes are not an <c>EncryptedPrivateKeyInfo</c>.</exception>
    public static string? WeaknessOf(ReadOnlyMemory<byte> encryptedPrivateKeyInfo)
    {
        var algorithm = new AsnReader(encryptedPrivateKeyInfo, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        if (algorithm.ReadObjectIdentifier() != Pbes2Oid)
            return "a legacy scheme rather than PBES2";

        var pbes2 = algorithm.ReadSequence();
        var kdf = pbes2.ReadSequence();
        if (kdf.ReadObjectIdentifier() != Pbkdf2Oid)
            return "a key derivation function other than PBKDF2";

        var kdfParameters = kdf.ReadSequence();
        kdfParameters.ReadEncodedValue();
        if (!kdfParameters.TryReadInt32(out var iterations) || iterations < MinimumIterations)
            return $"fewer than {MinimumIterations} PBKDF2 iterations";

        return AesCbcOids.Contains(pbes2.ReadSequence().ReadObjectIdentifier())
            ? null
            : "a cipher other than AES-CBC";
    }
}
