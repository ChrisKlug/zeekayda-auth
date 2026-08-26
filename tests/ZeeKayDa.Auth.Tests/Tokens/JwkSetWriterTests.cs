using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class JwkSetWriterTests
{
    // The RSA key RFC 7638 §3.1 uses for its worked thumbprint example — the same key as
    // RFC 7517 Appendix A.1's RSA entry — reproduced verbatim so serialising it verifies
    // interoperability with the specifications' own examples, not just internal consistency.
    private const string Rfc7638ModulusBase64Url =
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJEC" +
        "PebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz" +
        "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZ" +
        "u0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    private const string Rfc7638ExponentBase64Url = "AQAB";

    private const string Rfc7638ExpectedThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    // The EC key from RFC 7517 Appendix A.1's first entry, reproduced verbatim.
    private const string Rfc7517EcXBase64Url = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";

    private const string Rfc7517EcYBase64Url = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

    // ── Known-answer vectors ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Write_serialises_the_rfc7638_rsa_key_with_its_own_thumbprint_as_kid()
    {
        var keySet = BuildKeySet(current: RsaSourceKey("rsa", Rfc7638ModulusBase64Url, Rfc7638ExponentBase64Url));

        var jwk = SingleKey(JwkSetWriter.Write(keySet.Published));

        jwk.GetProperty("kid").GetString().Should().Be(Rfc7638ExpectedThumbprint);
        jwk.GetProperty("kty").GetString().Should().Be("RSA");
        jwk.GetProperty("use").GetString().Should().Be("sig");
        jwk.GetProperty("alg").GetString().Should().Be("RS256");
        jwk.GetProperty("n").GetString().Should().Be(Rfc7638ModulusBase64Url);
        jwk.GetProperty("e").GetString().Should().Be(Rfc7638ExponentBase64Url);
    }

    [Fact]
    public void Write_serialises_the_rfc7517_A1_ec_key_with_its_exact_coordinate_encodings()
    {
        var keySet = BuildKeySet(current: EcSourceKey("ec", Rfc7517EcXBase64Url, Rfc7517EcYBase64Url));

        var jwk = SingleKey(JwkSetWriter.Write(keySet.Published));

        jwk.GetProperty("kty").GetString().Should().Be("EC");
        jwk.GetProperty("use").GetString().Should().Be("sig");
        jwk.GetProperty("alg").GetString().Should().Be("ES256");
        jwk.GetProperty("crv").GetString().Should().Be("P-256");
        jwk.GetProperty("x").GetString().Should().Be(Rfc7517EcXBase64Url);
        jwk.GetProperty("y").GetString().Should().Be(Rfc7517EcYBase64Url);
    }

    [Fact]
    public void Write_encodes_a_zero_padded_modulus_minimally_so_the_served_n_rederives_the_kid()
    {
        var minimalModulus = DecodeBase64Url(Rfc7638ModulusBase64Url);
        var paddedModulus = new byte[minimalModulus.Length + 1];
        minimalModulus.CopyTo(paddedModulus, 1); // leading zero byte prepended

        var keySet = BuildKeySet(current: new SourceKey(
            new SourceKeyId("padded"),
            SigningAlgorithm.RS256,
            PublicKeyParameters.FromRsa(new RSAParameters
            {
                Modulus = paddedModulus,
                Exponent = DecodeBase64Url(Rfc7638ExponentBase64Url),
            }),
            ExpiresAt: null));

        var jwk = SingleKey(JwkSetWriter.Write(keySet.Published));

        jwk.GetProperty("n").GetString().Should().Be(Rfc7638ModulusBase64Url);
        jwk.GetProperty("kid").GetString().Should().Be(Rfc7638ExpectedThumbprint);
    }

    // ── Private material ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Write_emits_no_private_key_member_for_a_set_built_from_rsa_and_ec_private_keys()
    {
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keySet = BuildKeySet(
            previous: new SourceKey(
                new SourceKeyId("rsa"),
                SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: true)),
                ExpiresAt: null),
            current: new SourceKey(
                new SourceKeyId("ec"),
                SigningAlgorithm.ES256,
                PublicKeyParameters.FromEc(ec.ExportParameters(includePrivateParameters: true)),
                ExpiresAt: null));

        using var document = JsonDocument.Parse(JwkSetWriter.Write(keySet.Published));

        var allowedMembers = new[] { "kid", "kty", "use", "alg", "n", "e", "crv", "x", "y" };
        foreach (var jwk in document.RootElement.GetProperty("keys").EnumerateArray())
        {
            jwk.EnumerateObject().Select(member => member.Name)
                .Should().BeSubsetOf(allowedMembers);
        }
    }

    // ── Determinism and ordering ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Write_preserves_the_given_key_order()
    {
        var keySet = TestSigningKeys.KeySet(
            SigningAlgorithm.RS256, SigningAlgorithm.RS384, SigningAlgorithm.ES256);

        using var document = JsonDocument.Parse(JwkSetWriter.Write(keySet.Published));

        document.RootElement.GetProperty("keys").EnumerateArray()
            .Select(jwk => jwk.GetProperty("kid").GetString())
            .Should().Equal(keySet.Published.Select(key => key.Kid));
    }

    [Fact]
    public void Write_produces_byte_identical_output_for_the_same_key_list()
    {
        var keySet = TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256);

        var first = JwkSetWriter.Write(keySet.Published);
        var second = JwkSetWriter.Write(keySet.Published);

        second.Should().Equal(first);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static SigningKeySet BuildKeySet(SourceKey current, SourceKey? previous = null)
        => SigningKeySetBuilder.Build(SourceKeySet.Create(previous, current, next: null));

    private static SourceKey RsaSourceKey(string id, string modulusBase64Url, string exponentBase64Url)
        => new(
            new SourceKeyId(id),
            SigningAlgorithm.RS256,
            PublicKeyParameters.FromRsa(new RSAParameters
            {
                Modulus = DecodeBase64Url(modulusBase64Url),
                Exponent = DecodeBase64Url(exponentBase64Url),
            }),
            ExpiresAt: null);

    private static SourceKey EcSourceKey(string id, string xBase64Url, string yBase64Url)
        => new(
            new SourceKeyId(id),
            SigningAlgorithm.ES256,
            PublicKeyParameters.FromEc(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = DecodeBase64Url(xBase64Url),
                    Y = DecodeBase64Url(yBase64Url),
                },
            }),
            ExpiresAt: null);

    private static JsonElement SingleKey(byte[] jwkSetBytes)
    {
        using var document = JsonDocument.Parse(jwkSetBytes);
        var keys = document.RootElement.GetProperty("keys");
        keys.GetArrayLength().Should().Be(1);
        return keys[0].Clone();
    }

    private static byte[] DecodeBase64Url(string base64Url)
    {
        var input = Encoding.ASCII.GetBytes(base64Url);
        var decoded = new byte[Base64Url.GetMaxDecodedLength(input.Length)];
        Base64Url.DecodeFromUtf8(input, decoded, out _, out var written);
        return decoded.AsSpan(0, written).ToArray();
    }
}
