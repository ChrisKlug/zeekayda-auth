using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class JwkThumbprintTests
{
    // ── RSA — RFC 7638 Appendix A.1 known-answer vector ─────────────────────────────────────────

    // The exact modulus/exponent and expected thumbprint published in RFC 7638 Appendix A.1
    // (https://www.rfc-editor.org/rfc/rfc7638#section-3.1), reproduced verbatim so this test
    // verifies interoperability with the specification's own worked example, not just internal
    // self-consistency.
    private const string Rfc7638ModulusBase64Url =
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJEC" +
        "PebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz" +
        "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZ" +
        "u0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    private const string Rfc7638ExponentBase64Url = "AQAB";

    private const string Rfc7638ExpectedThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    [Fact]
    public void Compute_rsa_matches_rfc7638_known_answer_vector()
    {
        var rsaParams = new RSAParameters
        {
            Modulus = DecodeBase64Url(Rfc7638ModulusBase64Url),
            Exponent = DecodeBase64Url(Rfc7638ExponentBase64Url),
        };

        var thumbprint = JwkThumbprint.Compute(rsaParams);

        thumbprint.Should().Be(Rfc7638ExpectedThumbprint);
    }

    [Fact]
    public void Compute_rsa_is_deterministic()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var first = JwkThumbprint.Compute(rsaParams);
        var second = JwkThumbprint.Compute(rsaParams);

        second.Should().Be(first);
    }

    [Fact]
    public void Compute_rsa_differs_for_different_keys()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);

        var thumbprint1 = JwkThumbprint.Compute(rsa1.ExportParameters(false));
        var thumbprint2 = JwkThumbprint.Compute(rsa2.ExportParameters(false));

        thumbprint2.Should().NotBe(thumbprint1);
    }

    // ── EC — independently computed thumbprint ──────────────────────────────────────────────────

    [Fact]
    public void Compute_ec_matches_independently_computed_canonical_json_hash()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);

        var expected = IndependentlyComputeEcThumbprint(ecParams, "P-256");

        var thumbprint = JwkThumbprint.Compute(ecParams);

        thumbprint.Should().Be(expected);
    }

    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void Compute_ec_uses_correct_crv_name_for_each_supported_curve(string crvName)
    {
        var curve = crvName switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ec = ECDsa.Create(curve);
        var ecParams = ec.ExportParameters(false);

        var expected = IndependentlyComputeEcThumbprint(ecParams, crvName);

        var thumbprint = JwkThumbprint.Compute(ecParams);

        thumbprint.Should().Be(expected);
    }

    [Fact]
    public void Compute_ec_is_deterministic()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);

        var first = JwkThumbprint.Compute(ecParams);
        var second = JwkThumbprint.Compute(ecParams);

        second.Should().Be(first);
    }

    [Fact]
    public void Compute_ec_differs_for_different_keys()
    {
        using var ec1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ec2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var thumbprint1 = JwkThumbprint.Compute(ec1.ExportParameters(false));
        var thumbprint2 = JwkThumbprint.Compute(ec2.ExportParameters(false));

        thumbprint2.Should().NotBe(thumbprint1);
    }

    [Fact]
    public void Compute_ec_throws_NotSupportedException_for_unsupported_curve()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var unsupportedCurveParams = new ECParameters
        {
            Curve = ECCurve.CreateFromValue("1.2.840.10045.3.1.1"), // P-192 — not accepted
            Q = ecParams.Q,
        };

        var act = () => JwkThumbprint.Compute(unsupportedCurveParams);

        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Compute_ec_throws_NotSupportedException_for_null_curve_oid()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var nullOidParams = new ECParameters
        {
            Curve = new ECCurve(), // Oid is null on a default-constructed ECCurve
            Q = ecParams.Q,
        };

        var act = () => JwkThumbprint.Compute(nullOidParams);

        act.Should().Throw<NotSupportedException>();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the RFC 7638 EC thumbprint via a code path independent of
    /// <see cref="JwkThumbprint.Compute(ECParameters)"/>, to verify the production implementation
    /// without simply asserting it agrees with itself.
    /// </summary>
    private static string IndependentlyComputeEcThumbprint(ECParameters ecParams, string crv)
    {
        var x = EncodeBase64Url(ecParams.Q.X!);
        var y = EncodeBase64Url(ecParams.Q.Y!);

        // Manually built, member-sorted JSON string rather than reusing Utf8JsonWriter helpers
        // from the production code.
        var json = $$"""{"crv":"{{crv}}","kty":"EC","x":"{{x}}","y":"{{y}}"}""";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return EncodeBase64Url(hash);
    }

    private static byte[] DecodeBase64Url(string base64Url)
    {
        var input = Encoding.ASCII.GetBytes(base64Url);
        var decoded = new byte[Base64Url.GetMaxDecodedLength(input.Length)];
        Base64Url.DecodeFromUtf8(input, decoded, out _, out var written);
        return decoded[..written];
    }

    private static string EncodeBase64Url(byte[] input)
    {
        var encoded = new byte[Base64Url.GetEncodedLength(input.Length)];
        Base64Url.EncodeToUtf8(input, encoded);
        return Encoding.ASCII.GetString(encoded);
    }
}
