using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using ZeeKayDa.Auth.MacOS.Interop;

namespace ZeeKayDa.Auth.MacOS.Tests.Interop;

/// <summary>
/// Tests <see cref="EcdsaSignatureCodec"/> — pure managed code with no P/Invoke dependency, so unlike
/// the rest of this package's Security.framework interop, it is tested directly rather than only via
/// macOS-only integration tests.
/// </summary>
public sealed class EcdsaSignatureCodecTests
{
    [Theory]
    [InlineData(32)]
    [InlineData(48)]
    [InlineData(66)]
    public void DerToP1363_round_trips_a_real_ECDsa_signature_for_every_supported_field_size(int fieldSizeBytes)
    {
        var curve = fieldSizeBytes switch
        {
            32 => ECCurve.NamedCurves.nistP256,
            48 => ECCurve.NamedCurves.nistP384,
            66 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentOutOfRangeException(nameof(fieldSizeBytes)),
        };
        using var ecdsa = ECDsa.Create(curve);
        var hash = SHA256.HashData("zeekayda-ecdsa-codec-test"u8.ToArray());

        // Produce a real P1363 signature, then re-encode it as DER exactly as SecKeyCreateSignature
        // would return it, to prove DerToP1363 correctly inverts that encoding.
        var p1363 = ecdsa.SignHash(hash);
        var der = EncodeAsDer(p1363, fieldSizeBytes);

        var roundTripped = EcdsaSignatureCodec.DerToP1363(der, fieldSizeBytes);

        roundTripped.Should().Equal(p1363);
        ecdsa.VerifyHash(hash, roundTripped).Should().BeTrue();
    }

    [Fact]
    public void DerToP1363_produces_exactly_field_size_times_two_bytes_even_when_r_or_s_has_a_leading_zero()
    {
        // A component whose most-significant byte is >= 0x80 is DER-encoded with a leading 0x00 pad
        // byte (to keep the INTEGER non-negative), one byte longer than the field width - a case a
        // naive fixed-length copy would mishandle.
        var r = new BigInteger(1) << 255; // MSB set, forces a 33-byte unsigned DER encoding for a 32-byte field.
        var s = BigInteger.One;

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(r);
            writer.WriteInteger(s);
        }
        var der = writer.Encode();

        var p1363 = EcdsaSignatureCodec.DerToP1363(der, fieldSizeBytes: 32);

        p1363.Should().HaveCount(64);
    }

    [Fact]
    public void DerToP1363_right_aligns_a_component_shorter_than_the_field_width_with_leading_zero_padding()
    {
        // Regression test: BigInteger.TryWriteBytes does NOT right-align a value shorter than the
        // destination span - it writes at the front and leaves the true padding position (the front,
        // for big-endian) untouched, silently corrupting the signature unless the codec explicitly
        // right-aligns. Deterministic, fixed values (not a randomly generated key) per this
        // repository's test standard against relying on non-seeded randomness.
        var r = new BigInteger(0x01); // 1-byte minimal encoding, needs 31 leading zero bytes in a 32-byte field.
        var s = new BigInteger(0x0203); // 2-byte minimal encoding, needs 30 leading zero bytes.

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(r);
            writer.WriteInteger(s);
        }
        var der = writer.Encode();

        var p1363 = EcdsaSignatureCodec.DerToP1363(der, fieldSizeBytes: 32);

        var expectedR = new byte[32];
        expectedR[31] = 0x01;
        var expectedS = new byte[32];
        expectedS[30] = 0x02;
        expectedS[31] = 0x03;

        p1363.Should().HaveCount(64);
        p1363.AsSpan(0, 32).ToArray().Should().Equal(expectedR, "r must be right-aligned with leading zero padding, not left-aligned");
        p1363.AsSpan(32, 32).ToArray().Should().Equal(expectedS, "s must be right-aligned with leading zero padding, not left-aligned");
    }

    private static byte[] EncodeAsDer(byte[] p1363, int fieldSizeBytes)
    {
        var r = new BigInteger(p1363.AsSpan(0, fieldSizeBytes), isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(p1363.AsSpan(fieldSizeBytes, fieldSizeBytes), isUnsigned: true, isBigEndian: true);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(r);
            writer.WriteInteger(s);
        }

        return writer.Encode();
    }
}
