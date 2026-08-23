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
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.SigningKey.SourceId.Should().Be(current.Id);
    }

    [Fact]
    public void Build_returns_a_set_whose_published_list_contains_every_configured_key()
    {
        var previous = CreateRsaSourceKey("previous");
        var current = CreateRsaSourceKey("current");
        var next = CreateRsaSourceKey("next");
        var keys = SourceKeySet.FromSlots(previous, current, next);

        var set = SigningKeySetBuilder.Build(keys);

        set.Published.Select(k => k.SourceId).Should().BeEquivalentTo([previous.Id, current.Id, next.Id]);
    }

    [Fact]
    public void Build_with_only_Current_produces_a_set_with_a_single_published_key()
    {
        var current = CreateRsaSourceKey("current");
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.Published.Should().ContainSingle(k => k.SourceId == current.Id);
    }

    [Fact]
    public void Build_derives_Kid_as_the_RFC7638_thumbprint_of_the_public_key()
    {
        var current = CreateRsaSourceKey("current");
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

        var set = SigningKeySetBuilder.Build(keys);

        set.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(current.PublicKey.RsaPublicParameters!.Value));
    }

    [Fact]
    public void Build_advertised_algorithms_are_the_distinct_published_algorithms_in_ascending_order()
    {
        var previous = CreateEcSourceKey("previous", ECCurve.NamedCurves.nistP521, SigningAlgorithm.ES512);
        var current = CreateRsaSourceKey("current", algorithm: SigningAlgorithm.RS256);
        var next = CreateEcSourceKey("next", ECCurve.NamedCurves.nistP256, SigningAlgorithm.ES256);
        var keys = SourceKeySet.FromSlots(previous, current, next);

        var set = SigningKeySetBuilder.Build(keys);

        set.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.ES512);
    }

    [Fact]
    public void Build_advertised_algorithms_deduplicates_when_multiple_keys_share_an_algorithm()
    {
        var previous = CreateRsaSourceKey("previous", algorithm: SigningAlgorithm.RS256);
        var current = CreateRsaSourceKey("current", algorithm: SigningAlgorithm.RS256);
        var keys = SourceKeySet.FromSlots(previous, current, next: null);

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
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

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

        var previous = new SourceKey(new KeyId("previous"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var current = new SourceKey(new KeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.FromSlots(previous, current, next: null);

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
        var current = new SourceKey(new KeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
    }

    [Fact]
    public void Build_throws_when_an_EC_algorithm_is_declared_over_an_RSA_public_key()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        var current = new SourceKey(new KeyId("current"), SigningAlgorithm.ES256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
    }

    [Fact]
    public void Build_throws_when_the_EC_algorithm_does_not_match_the_key_curve()
    {
        // ES256 requires P-256; the key is P-384.
        var current = CreateEcSourceKey("current", ECCurve.NamedCurves.nistP384, SigningAlgorithm.ES256);
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.ec_curve_algorithm_mismatch");
    }

    // ── Validation: key strength ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_the_RSA_modulus_is_below_2048_bits()
    {
        using var rsa = RSA.Create(1024);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        var current = new SourceKey(new KeyId("current"), SigningAlgorithm.RS256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

        var act = () => SigningKeySetBuilder.Build(keys);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.rsa_key_too_small");
    }

    [Fact]
    public void Build_rejects_a_non_NIST_curve_at_build_time_before_any_private_material_exists()
    {
        // Kid derivation runs before key-strength validation, and JwkThumbprint's own
        // supported-curve set is the same three NIST curves SigningAlgorithms accepts — so a
        // non-NIST curve is rejected at the derivation step, before any private key material
        // exists, but still surfaces as ZeeKayDaConfigurationException like every other rejection.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var unsupportedCurveParams = new ECParameters
        {
            Curve = ECCurve.CreateFromValue("1.2.840.10045.3.1.1"), // P-192 — not accepted
            Q = ec.ExportParameters(false).Q,
        };
        var publicKey = PublicKeyParameters.FromEc(unsupportedCurveParams);
        var current = new SourceKey(new KeyId("current"), SigningAlgorithm.ES256, publicKey, ExpiresAt: null);
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);

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
        return new SourceKey(new KeyId(id), algorithm, publicKey, expiresAt ?? Now.AddDays(90));
    }

    private static SourceKey CreateEcSourceKey(string id, ECCurve curve, SigningAlgorithm algorithm, DateTimeOffset? expiresAt = null)
    {
        using var ec = ECDsa.Create(curve);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));
        return new SourceKey(new KeyId(id), algorithm, publicKey, expiresAt ?? Now.AddDays(90));
    }
}
