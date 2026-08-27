using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningAlgorithms"/>'s surviving <see cref="PublicKeyParameters"/> surface
/// directly. Issue #511 deleted the <c>SigningKeyDescriptor</c> overloads and the
/// <c>JwtSigningService&lt;TOptions&gt;</c> tests that reached the RSA/EC sign and verify arms
/// through them; these cover the same arms against the contract that survives.
/// </summary>
/// <remarks>
/// Each test creates and owns its own key under a <see langword="using"/> rather than taking one
/// from a helper. A helper returning a live <see cref="AsymmetricAlgorithm"/> transfers ownership
/// out of the method, which CodeQL cannot follow and reports as an undisposed local.
/// </remarks>
public sealed class SigningAlgorithmsTests
{
    private static readonly byte[] SigningInput = Encoding.UTF8.GetBytes("signing-input");

    // ── Sign/verify round trip, every supported algorithm ────────────────────────────────────────

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.RS384)]
    [InlineData(SigningAlgorithm.RS512)]
    [InlineData(SigningAlgorithm.PS256)]
    [InlineData(SigningAlgorithm.PS384)]
    [InlineData(SigningAlgorithm.PS512)]
    public void Sign_then_Verify_round_trips_for_every_RSA_algorithm(SigningAlgorithm algorithm)
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));

        var signature = SigningAlgorithms.Sign(algorithm, SigningInput, rsa);

        SigningAlgorithms.Verify(algorithm, publicKey, SigningInput, signature.Span).Should().BeTrue();
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256, "nistP256")]
    [InlineData(SigningAlgorithm.ES384, "nistP384")]
    [InlineData(SigningAlgorithm.ES512, "nistP521")]
    public void Sign_then_Verify_round_trips_for_every_EC_algorithm(SigningAlgorithm algorithm, string curveName)
    {
        using var ec = ECDsa.Create(ECCurve.CreateFromFriendlyName(curveName));
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));

        var signature = SigningAlgorithms.Sign(algorithm, SigningInput, ec);

        SigningAlgorithms.Verify(algorithm, publicKey, SigningInput, signature.Span).Should().BeTrue();
    }

    [Fact]
    public void Verify_returns_false_for_an_RSA_signature_over_different_input()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        var signature = SigningAlgorithms.Sign(SigningAlgorithm.RS256, SigningInput, rsa);

        var tampered = Encoding.UTF8.GetBytes("different-input");

        SigningAlgorithms.Verify(SigningAlgorithm.RS256, publicKey, tampered, signature.Span).Should().BeFalse();
    }

    [Fact]
    public void Verify_returns_false_for_an_EC_signature_over_different_input()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));
        var signature = SigningAlgorithms.Sign(SigningAlgorithm.ES256, SigningInput, ec);

        var tampered = Encoding.UTF8.GetBytes("different-input");

        SigningAlgorithms.Verify(SigningAlgorithm.ES256, publicKey, tampered, signature.Span).Should().BeFalse();
    }

    /// <summary>
    /// RFC 7518 §3.4 requires IEEE P1363 (raw R||S), not the DER sequence .NET defaults to. A DER
    /// signature is the wrong length, so this pins the format rather than merely that it verifies.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithm.ES256, "nistP256", 64)]
    [InlineData(SigningAlgorithm.ES384, "nistP384", 96)]
    [InlineData(SigningAlgorithm.ES512, "nistP521", 132)]
    public void Sign_produces_IEEE_P1363_EC_signatures(SigningAlgorithm algorithm, string curveName, int expectedLength)
    {
        using var ec = ECDsa.Create(ECCurve.CreateFromFriendlyName(curveName));

        var signature = SigningAlgorithms.Sign(algorithm, SigningInput, ec);

        signature.Length.Should().Be(expectedLength);
    }

    // ── Key strength: significant-bit counting ───────────────────────────────────────────────────

    [Fact]
    public void ValidateKeyStrength_rejects_an_all_zero_RSA_modulus()
    {
        // An all-zero modulus has zero significant bits however long its byte array is — a
        // 384-byte buffer of zeros must not pass as a 3072-bit key.
        var publicKey = PublicKeyParameters.FromRsa(new RSAParameters
        {
            Modulus = new byte[384],
            Exponent = [1, 0, 1],
        });

        var act = () => SigningAlgorithms.ValidateKeyStrength(SigningAlgorithm.RS256, publicKey, "test-key");

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures[0].Code.Should().Be("signing.rsa_key_too_small");
    }

    [Fact]
    public void ValidateKeyStrength_rejects_a_modulus_just_under_2048_significant_bits()
    {
        // 256 bytes whose leading byte is 0x01: 255 * 8 + 1 = 2041 significant bits. The count
        // must come from the most-significant SET bit, not from the byte length (which would
        // read as 2048) — a boundary an off-by-one in the bit counting walks straight past.
        var modulus = new byte[256];
        modulus[0] = 0x01;
        modulus[255] = 0x01;
        var publicKey = PublicKeyParameters.FromRsa(new RSAParameters
        {
            Modulus = modulus,
            Exponent = [1, 0, 1],
        });

        var act = () => SigningAlgorithms.ValidateKeyStrength(SigningAlgorithm.RS256, publicKey, "test-key");

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures[0].Code.Should().Be("signing.rsa_key_too_small");
    }

    // ── Key/algorithm compatibility: EC curve pairing ────────────────────────────────────────────

    [Theory]
    [InlineData(SigningAlgorithm.ES256, "nistP256")]
    [InlineData(SigningAlgorithm.ES384, "nistP384")]
    [InlineData(SigningAlgorithm.ES512, "nistP521")]
    public void ValidateKeyAlgorithmCompatibility_accepts_an_EC_key_on_its_matching_curve(
        SigningAlgorithm algorithm, string curveName)
    {
        using var ec = ECDsa.Create(ECCurve.CreateFromFriendlyName(curveName));
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));

        var act = () => SigningAlgorithms.ValidateKeyAlgorithmCompatibility(algorithm, publicKey, "test-key");

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateKeyAlgorithmCompatibility_rejects_an_EC_key_whose_curve_does_not_match_the_algorithm()
    {
        // ES256 requires P-256 (RFC 7518 §3.4); a P-384 key under ES256 is a misconfiguration,
        // reported with the stable failure code rather than accepted or crashed on.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));

        var act = () => SigningAlgorithms.ValidateKeyAlgorithmCompatibility(SigningAlgorithm.ES256, publicKey, "test-key");

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures[0].Code.Should().Be("signing.ec_curve_algorithm_mismatch");
    }

    // ── Unsupported algorithm values ─────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_throws_for_an_RSA_key_under_an_out_of_range_algorithm()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));

        var act = () => SigningAlgorithms.Verify((SigningAlgorithm)9999, publicKey, SigningInput, SigningInput);

        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Verify_throws_for_an_EC_key_under_an_out_of_range_algorithm()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));

        var act = () => SigningAlgorithms.Verify((SigningAlgorithm)9999, publicKey, SigningInput, SigningInput);

        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Sign_throws_for_an_out_of_range_algorithm()
    {
        using var rsa = RSA.Create(2048);

        var act = () => SigningAlgorithms.Sign((SigningAlgorithm)9999, SigningInput, rsa);

        act.Should().Throw<NotSupportedException>();
    }
    [Fact]
    public void WireName_matches_the_JsonStringEnumMemberName_for_every_member()
    {
        // The JWS alg header must be the exact identifier STJ serialises into the discovery
        // document and JWKS — one source of truth, even for a future member whose C# name
        // cannot be the RFC 7518 id verbatim.
        foreach (var algorithm in Enum.GetValues<SigningAlgorithm>())
        {
            var attribute = typeof(SigningAlgorithm).GetField(algorithm.ToString())!
                .GetCustomAttributes(typeof(System.Text.Json.Serialization.JsonStringEnumMemberNameAttribute), inherit: false)
                .Cast<System.Text.Json.Serialization.JsonStringEnumMemberNameAttribute>()
                .Single();

            SigningAlgorithms.WireName(algorithm).Should().Be(attribute.Name);
        }
    }

}
