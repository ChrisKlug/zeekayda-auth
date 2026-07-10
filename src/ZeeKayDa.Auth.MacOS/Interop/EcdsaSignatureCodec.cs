using System.Formats.Asn1;

namespace ZeeKayDa.Auth.MacOS.Interop;

/// <summary>
/// Converts an ECDSA signature between DER (ANSI X9.62 <c>SEQUENCE{r INTEGER, s INTEGER}</c>) and
/// IEEE P1363 fixed-width <c>r||s</c> big-endian concatenation.
/// </summary>
/// <remarks>
/// <para>
/// <c>SecKeyCreateSignature</c>'s ECDSA "Digest" algorithms (<c>kSecKeyAlgorithmECDSASignatureDigestX962SHA*</c>)
/// always return the DER encoding — Security.framework has no fixed-width output option. .NET's
/// <see cref="System.Security.Cryptography.ECDsa.SignHash(byte[])"/> contract (and therefore RFC 7518
/// §3.4's required JWS format) is the fixed-width concatenation instead, so every signature produced
/// by <see cref="SecKeyBackedECDsa"/> is converted through this class before being returned.
/// </para>
/// <para>
/// This class is pure managed code with no P/Invoke dependency, so — unlike the rest of this
/// package's Security.framework interop — it is unit-tested directly, on any OS, against known-good
/// DER signatures.
/// </para>
/// </remarks>
internal static class EcdsaSignatureCodec
{
    /// <summary>
    /// Converts a DER-encoded ECDSA signature to IEEE P1363 fixed-width <c>r||s</c>, padded (or, in
    /// the vanishingly rare case a coordinate's encoding is one byte too long, trimmed of a leading
    /// zero) to exactly <paramref name="fieldSizeBytes"/> bytes each.
    /// </summary>
    /// <param name="der">The DER (ANSI X9.62) encoded signature.</param>
    /// <param name="fieldSizeBytes">The curve's field size in bytes (32 for P-256, 48 for P-384, 66 for P-521).</param>
    /// <returns>The fixed-width <c>r||s</c> signature, <c>fieldSizeBytes * 2</c> bytes long.</returns>
    public static byte[] DerToP1363(ReadOnlyMemory<byte> der, int fieldSizeBytes)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        var r = sequence.ReadInteger();
        var s = sequence.ReadInteger();

        var result = new byte[fieldSizeBytes * 2];
        WriteFixedWidthUnsignedBigEndian(r, result.AsSpan(0, fieldSizeBytes));
        WriteFixedWidthUnsignedBigEndian(s, result.AsSpan(fieldSizeBytes, fieldSizeBytes));
        return result;
    }

    // BigInteger.TryWriteBytes does NOT right-align a value that is shorter than the destination
    // span: it writes the value's minimal big-endian encoding starting at destination[0] and leaves
    // the remaining trailing bytes untouched, which is the wrong end to pad for a big-endian
    // fixed-width integer (the padding zeros belong at the front, not the back). A naive
    // `value.TryWriteBytes(destination, ...)` call therefore silently corrupts every r/s component
    // whose minimal encoding is shorter than the field width — which is common (each component is
    // ~1/256 likely to need one byte fewer per leading zero byte, and P-521's 66-byte field is not
    // byte-aligned to its ~521-bit curve order, making a short top byte routine, not rare). This was
    // caught by EcdsaSignatureCodecTests exercising many real P-521 signatures, not by inspection.
    private static void WriteFixedWidthUnsignedBigEndian(System.Numerics.BigInteger value, Span<byte> destination)
    {
        destination.Clear();

        var byteCount = value.GetByteCount(isUnsigned: true);
        if (byteCount > destination.Length)
        {
            throw new CryptographicSignatureFormatException(
                $"ECDSA signature component needs {byteCount} bytes, which does not fit in the expected " +
                $"{destination.Length}-byte field width.");
        }

        var target = destination[(destination.Length - byteCount)..];
        if (!value.TryWriteBytes(target, out var written, isUnsigned: true, isBigEndian: true) || written != byteCount)
        {
            throw new CryptographicSignatureFormatException(
                $"ECDSA signature component did not fit in the expected {destination.Length}-byte field width.");
        }
    }
}

/// <summary>Thrown when a signature produced by the Keychain cannot be converted to the format a caller requires.</summary>
internal sealed class CryptographicSignatureFormatException(string message) : Exception(message);
