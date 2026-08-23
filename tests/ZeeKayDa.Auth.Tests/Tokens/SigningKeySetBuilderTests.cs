using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeySetBuilder.Build"/> directly, with no test double of any kind —
/// every validation and projection is proven against the builder itself, per issue #506's explicit
/// acceptance criterion.
/// </summary>
public sealed class SigningKeySetBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Projection ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Build_returns_a_set_whose_signing_key_is_the_Current_slot_key()
    {
        var current = CreateRsaSourceKey("current");
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.SigningKey.SourceId.Should().Be(current.Id);
    }

    [Fact]
    public void Build_returns_a_set_whose_published_list_contains_every_configured_key()
    {
        var previous = CreateRsaSourceKey("previous");
        var current = CreateRsaSourceKey("current");
        var next = CreateRsaSourceKey("next");
        var keys = SourceKeySet.Create(previous, current, next);

        var set = SigningKeySetBuilder.Build(keys);

        set.Published.Select(k => k.SourceId).Should().BeEquivalentTo([previous.Id, current.Id, next.Id]);
    }

    [Fact]
    public void Build_with_only_Current_produces_a_set_with_a_single_published_key()
    {
        var current = CreateRsaSourceKey("current");
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.Published.Should().ContainSingle(k => k.SourceId == current.Id);
    }

    [Fact]
    public void Build_derives_Kid_as_the_RFC7638_thumbprint_of_the_public_key()
    {
        var current = CreateRsaSourceKey("current");
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(current.PublicKey.RsaPublicParameters!.Value));
    }

    [Fact]
    public void Build_advertised_algorithms_are_the_distinct_published_algorithms_in_ascending_order()
    {
        var previous = CreateEcSourceKey("previous", ECCurve.NamedCurves.nistP521, SigningAlgorithm.ES512);
        var current = CreateRsaSourceKey("current", algorithm: SigningAlgorithm.RS256);
        var next = CreateEcSourceKey("next", ECCurve.NamedCurves.nistP256, SigningAlgorithm.ES256);
        var keys = SourceKeySet.Create(previous, current, next);

        var set = SigningKeySetBuilder.Build(keys);

        set.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.ES512);
    }

    [Fact]
    public void Build_advertised_algorithms_deduplicates_when_multiple_keys_share_an_algorithm()
    {
        var previous = CreateRsaSourceKey("previous", algorithm: SigningAlgorithm.RS256);
        var current = CreateRsaSourceKey("current", algorithm: SigningAlgorithm.RS256);
        var keys = SourceKeySet.Create(previous, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256);
    }

    [Fact]
    public void Build_throws_ArgumentNullException_when_keys_is_null()
    {
        var act = () => SigningKeySetBuilder.Build(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Validation: source id ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Build_throws_when_a_source_id_is_empty_or_whitespace(string emptyId)
    {
        var current = CreateRsaSourceKey(emptyId);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.empty_key_id");
    }

    [Fact]
    public void Build_throws_when_two_keys_share_a_source_id()
    {
        var current = CreateRsaSourceKey("dup");
        var next = CreateRsaSourceKey("dup");
        var keys = new SourceKeySet(current, next);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.duplicate_key_id");
    }

    // ── Validation: kid ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_two_distinct_source_ids_derive_the_same_kid()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));

        var previous = new SourceKey(new SourceKeyId("previous"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.duplicate_kid");
    }

    // ── Validation: algorithm/key-type compatibility ────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_an_RSA_algorithm_is_declared_over_an_EC_public_key()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
    }

    [Fact]
    public void Build_validation_failure_messages_name_the_configured_source_id_not_the_derived_kid()
    {
        // The operator typed "current" (SourceKey.Id) and never sees the derived kid — every
        // validation message must be keyed on the id they actually configured.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Message.Contains("'current'"));
    }

    [Fact]
    public void Build_throws_when_an_EC_algorithm_is_declared_over_an_RSA_public_key()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.ES256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
    }

    [Fact]
    public void Build_throws_when_the_EC_algorithm_does_not_match_the_key_curve()
    {
        // ES256 requires P-256; the key is P-384.
        var current = CreateEcSourceKey("current", ECCurve.NamedCurves.nistP384, SigningAlgorithm.ES256);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.ec_curve_algorithm_mismatch");
    }

    // ── Public key material is immutable once built ─────────────────────────────────────────────

    [Fact]
    public void Build_result_is_immune_to_mutating_every_reachable_RSA_public_key_accessor()
    {
        var current = CreateRsaSourceKey("current");
        var keys = SourceKeySet.Create(previous: null, current, next: null);
        var set = SigningKeySetBuilder.Build(keys);
        var originalKid = set.SigningKey.Kid;

        // A malicious component resolving the built set and mutating whatever it can reach: every
        // accessor returns a fresh copy, so none of this can move the recomputed kid.
        var rsaParams = set.SigningKey.PublicKey.RsaPublicParameters!.Value;
        rsaParams.Modulus![0] ^= 0xFF;
        rsaParams.Exponent![0] ^= 0xFF;

        JwkThumbprint.Compute(set.SigningKey.PublicKey.RsaPublicParameters!.Value).Should().Be(originalKid);
        set.SigningKey.Kid.Should().Be(originalKid);
    }

    [Fact]
    public void Build_result_is_immune_to_mutating_every_reachable_EC_public_key_accessor()
    {
        var current = CreateEcSourceKey("current", ECCurve.NamedCurves.nistP256, SigningAlgorithm.ES256);
        var keys = SourceKeySet.Create(previous: null, current, next: null);
        var set = SigningKeySetBuilder.Build(keys);
        var originalKid = set.SigningKey.Kid;

        var ecParams = set.SigningKey.PublicKey.EcPublicParameters!.Value;
        ecParams.Q.X![0] ^= 0xFF;
        ecParams.Q.Y![0] ^= 0xFF;

        JwkThumbprint.Compute(set.SigningKey.PublicKey.EcPublicParameters!.Value).Should().Be(originalKid);
        set.SigningKey.Kid.Should().Be(originalKid);
    }

    [Fact]
    public void Build_does_not_share_the_source_s_PublicKeyParameters_instance_with_the_built_SigningKey()
    {
        var current = CreateRsaSourceKey("current");
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.SigningKey.PublicKey.Should().NotBeSameAs(current.PublicKey);
    }

    // ── Validation: undefined algorithm ──────────────────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_the_declared_algorithm_is_not_a_defined_SigningAlgorithm_member()
    {
        var current = CreateRsaSourceKey("current", algorithm: (SigningAlgorithm)999);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.undefined_algorithm");
    }

    // ── Validation: structural public-key garbage ────────────────────────────────────────────────

    [Fact]
    public void Build_throws_signing_invalid_public_key_for_an_off_curve_EC_point()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validParams = ec.ExportParameters(false);
        var offCurveParams = new ECParameters
        {
            Curve = validParams.Curve,
            Q = new ECPoint
            {
                X = validParams.Q.X,
                Y = (byte[])validParams.Q.Y!.Clone(),
            },
        };
        offCurveParams.Q.Y![^1] ^= 0x01; // perturb Y so (X, Y) is very unlikely to remain on the curve
        var publicKey = PublicKeyParameters.FromEc(offCurveParams);
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.ES256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.invalid_public_key");
    }

    [Fact]
    public void Build_throws_signing_invalid_public_key_for_an_all_zero_RSA_modulus()
    {
        var publicKey = PublicKeyParameters.FromRsa(new RSAParameters
        {
            Modulus = new byte[256], // all-zero, 2048 bits by length, structurally not a public key
            Exponent = [0x01, 0x00, 0x01],
        });
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(
                f => f.Code == "signing.rsa_key_too_small" || f.Code == "signing.invalid_public_key");
    }

    // ── Validation: key strength ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_the_RSA_modulus_is_below_2048_bits()
    {
        using var rsa = RSA.Create(1024);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.rsa_key_too_small");
    }

    [Fact]
    public void Build_throws_when_an_RSA_modulus_is_left_padded_to_look_like_2048_bits()
    {
        // A 1024-bit modulus left-padded with zero bytes to a 256-byte (2048-bit) array. Counting
        // significant bits (not byte length) must still reject this as too small.
        using var rsa = RSA.Create(1024);
        var smallModulus = rsa.ExportParameters(false).Modulus!;
        var paddedModulus = new byte[256];
        smallModulus.CopyTo(paddedModulus, 256 - smallModulus.Length);
        var publicKey = PublicKeyParameters.FromRsa(new RSAParameters { Modulus = paddedModulus, Exponent = [0x01, 0x00, 0x01] });
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.rsa_key_too_small");
    }

    [Fact]
    public void Build_rejects_a_non_NIST_curve_at_build_time_before_any_private_material_exists()
    {
        // Key-strength validation runs before kid derivation, so a non-NIST curve is rejected there,
        // before any private key material exists and before JwkThumbprint ever sees the curve.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var unsupportedCurveParams = new ECParameters
        {
            Curve = ECCurve.CreateFromValue("1.2.840.10045.3.1.1"), // P-192 — not accepted
            Q = ec.ExportParameters(false).Q,
        };
        var publicKey = PublicKeyParameters.FromEc(unsupportedCurveParams);
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.ES256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.Create(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.ec_unsupported_curve");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static SourceKey CreateRsaSourceKey(
        string id, int keySize = 2048, SigningAlgorithm algorithm = SigningAlgorithm.RS256, DateTimeOffset? expiresAt = null)
    {
        using var rsa = RSA.Create(keySize);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        return new SourceKey(new SourceKeyId(id), algorithm, publicKey, expiresAt ?? Now.AddDays(90));
    }

    private static SourceKey CreateEcSourceKey(string id, ECCurve curve, SigningAlgorithm algorithm, DateTimeOffset? expiresAt = null)
    {
        using var ec = ECDsa.Create(curve);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));
        return new SourceKey(new SourceKeyId(id), algorithm, publicKey, expiresAt ?? Now.AddDays(90));
    }
}
