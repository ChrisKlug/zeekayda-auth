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
}
