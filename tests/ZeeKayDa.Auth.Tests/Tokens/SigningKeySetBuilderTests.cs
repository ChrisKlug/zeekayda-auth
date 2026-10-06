using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeySetBuilder.Build"/> directly: every validation, and every timing
/// rule that decides which key signs and which keys are published.
/// </summary>
public sealed class SigningKeySetBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly TimeSpan LeadTime = TimeSpan.FromDays(1);

    private static readonly TimeSpan Retention = TimeSpan.FromHours(1);

    // Past the lead time but inside the retention period: the key signs and the key before it stays published.
    private static readonly DateTimeOffset SigningInsideRetention = Now - LeadTime - TimeSpan.FromMinutes(30);

    // ── Which key signs ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Build_signs_with_the_newest_key_past_the_lead_time()
    {
        var older = CreateRsaSourceKey("older", notBefore: Now.AddDays(-30));
        var newest = CreateRsaSourceKey("newest", notBefore: Now - LeadTime);

        var set = Build(older, newest);

        set.SigningKey.SourceId.Should().Be(newest.Id);
    }

    [Fact]
    public void Build_does_not_sign_with_a_key_inside_its_lead_time_while_an_older_key_is_past_it()
    {
        var current = CreateRsaSourceKey("current", notBefore: Now.AddDays(-30));
        var staged = CreateRsaSourceKey("staged", notBefore: Now - LeadTime + TimeSpan.FromSeconds(1));

        var set = Build(current, staged);

        set.SigningKey.SourceId.Should().Be(current.Id);
        set.Published.Select(k => k.SourceId).Should().Contain(staged.Id);
    }

    [Fact]
    public void Build_signs_with_the_oldest_valid_key_and_logs_a_warning_when_no_key_is_past_the_lead_time()
    {
        var oldest = CreateRsaSourceKey("oldest", notBefore: Now.AddHours(-3));
        var newer = CreateRsaSourceKey("newer", notBefore: Now.AddHours(-1));
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();

        var set = Build(logger, oldest, newer);

        set.SigningKey.SourceId.Should().Be(oldest.Id);
        logger.Warnings.Should().ContainSingle().Which.Should().Contain(set.SigningKey.Kid);
    }

    [Fact]
    public void Build_logs_no_warning_when_the_signing_key_is_past_the_lead_time()
    {
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();

        Build(logger, CreateRsaSourceKey("current", notBefore: Now - LeadTime));

        logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Build_signs_with_a_single_undated_key_at_once_without_a_warning()
    {
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var only = CreateRsaSourceKey("only");

        var set = Build(logger, only);

        set.SigningKey.SourceId.Should().Be(only.Id);
        logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Build_breaks_a_tie_on_NotBefore_by_treating_the_ordinally_greater_source_id_as_newer()
    {
        var date = Now.AddDays(-2);
        var b = CreateRsaSourceKey("b", notBefore: date);
        var a = CreateRsaSourceKey("a", notBefore: date);

        Build(b, a).SigningKey.SourceId.Should().Be(b.Id);
        Build(a, b).SigningKey.SourceId.Should().Be(b.Id);
    }

    [Fact]
    public void Build_signs_with_a_key_whose_NotBefore_is_within_five_minutes_in_the_future()
    {
        var only = CreateRsaSourceKey("only", notBefore: Now.AddMinutes(5));

        Build(only).SigningKey.SourceId.Should().Be(only.Id);
    }

    [Fact]
    public void Build_publishes_a_key_not_yet_valid_but_never_signs_with_it()
    {
        var current = CreateRsaSourceKey("current", notBefore: Now.AddDays(-30));
        var future = CreateRsaSourceKey("future", notBefore: Now.AddDays(3));

        var set = Build(current, future);

        set.SigningKey.SourceId.Should().Be(current.Id);
        set.Published.Select(k => k.SourceId).Should().Contain(future.Id);
    }

    [Fact]
    public void Build_fails_with_signing_key_not_yet_valid_when_every_key_is_more_than_five_minutes_in_the_future()
    {
        var act = () => Build(CreateRsaSourceKey("future", notBefore: Now.AddMinutes(5).AddSeconds(1)));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signing_key_not_yet_valid");
    }

    [Fact]
    public void Build_fails_with_signing_key_expired_when_every_key_has_expired()
    {
        var act = () => Build(
            CreateRsaSourceKey("old", notBefore: Now.AddDays(-30), expiresAt: Now.AddDays(-2)),
            CreateRsaSourceKey("current", notBefore: Now.AddDays(-20), expiresAt: Now));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signing_key_expired");
    }

    [Fact]
    public void Build_does_not_publish_a_key_that_expired_the_retention_or_more_ago()
    {
        var expired = CreateRsaSourceKey("expired", notBefore: Now.AddDays(-2), expiresAt: Now - Retention);
        var older = CreateRsaSourceKey("older", notBefore: Now.AddDays(-30));

        var set = Build(older, expired);

        set.SigningKey.SourceId.Should().Be(older.Id);
        set.Published.Select(k => k.SourceId).Should().Equal(older.Id);
    }

    [Fact]
    public void Build_publishes_a_key_that_expired_less_than_the_retention_ago_but_never_signs_with_it()
    {
        // A token it signed just before expiring is still in force for up to a token lifetime.
        var expired = CreateRsaSourceKey("expired", notBefore: Now.AddDays(-2), expiresAt: Now - Retention + TimeSpan.FromSeconds(1));
        var older = CreateRsaSourceKey("older", notBefore: Now.AddDays(-30));

        var set = Build(older, expired);

        set.SigningKey.SourceId.Should().Be(older.Id);
        set.Published.Select(k => k.SourceId).Should().Equal(older.Id, expired.Id);
    }

    // ── Which keys are published ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Build_keeps_an_old_key_published_until_its_successor_is_past_the_lead_time_plus_retention()
    {
        var old = CreateRsaSourceKey("old", notBefore: Now.AddDays(-30));
        var successor = CreateRsaSourceKey("successor", notBefore: Now - LeadTime - Retention + TimeSpan.FromSeconds(1));

        var set = Build(old, successor);

        set.SigningKey.SourceId.Should().Be(successor.Id);
        set.Published.Select(k => k.SourceId).Should().Equal(old.Id, successor.Id);
    }

    [Fact]
    public void Build_drops_a_key_older_than_the_predecessor_once_a_newer_key_is_past_the_lead_time_plus_retention()
    {
        var oldest = CreateRsaSourceKey("oldest", notBefore: Now.AddDays(-30));
        var predecessor = CreateRsaSourceKey("predecessor", notBefore: Now.AddDays(-20));
        var signing = CreateRsaSourceKey("signing", notBefore: Now - LeadTime - Retention);

        var set = Build(oldest, predecessor, signing);

        set.SigningKey.SourceId.Should().Be(signing.Id);
        set.Published.Select(k => k.SourceId).Should().Equal(predecessor.Id, signing.Id);
    }

    [Fact]
    public void Build_keeps_the_signing_keys_predecessor_published_however_long_the_signing_key_has_been_ready()
    {
        // The ring reads keys only at startup: the successor took over at this restart, not when its
        // lead time ended, so the predecessor may have signed tokens until a moment ago.
        var predecessor = CreateRsaSourceKey("predecessor", notBefore: Now.AddDays(-30));
        var signing = CreateRsaSourceKey("signing", notBefore: Now.AddDays(-10));

        var set = Build(predecessor, signing);

        set.SigningKey.SourceId.Should().Be(signing.Id);
        set.Published.Select(k => k.SourceId).Should().Equal(predecessor.Id, signing.Id);
    }

    [Fact]
    public void Build_keeps_the_newest_live_predecessor_published_when_a_long_expired_key_sits_between_it_and_the_signing_key()
    {
        var predecessor = CreateRsaSourceKey("predecessor", notBefore: Now.AddDays(-100));
        var expired = CreateRsaSourceKey("expired", notBefore: Now.AddDays(-50), expiresAt: Now.AddDays(-30));
        var signing = CreateRsaSourceKey("signing", notBefore: Now.AddDays(-10));

        var set = Build(predecessor, expired, signing);

        set.Published.Select(k => k.SourceId).Should().Equal(predecessor.Id, signing.Id);
    }

    [Fact]
    public void Build_does_not_overflow_when_lead_time_plus_retention_exceeds_TimeSpan_MaxValue()
    {
        var oldest = CreateRsaSourceKey("oldest", notBefore: Now.AddDays(-30));
        var predecessor = CreateRsaSourceKey("predecessor", notBefore: Now.AddDays(-20));
        var signing = CreateRsaSourceKey("signing", notBefore: Now.AddDays(-10));
        var options = new SigningKeyOptions { LeadTime = LeadTime, RetainRetiredKeysFor = TimeSpan.MaxValue };

        var set = SigningKeySetBuilder.Build([oldest, predecessor, signing], Now, options, NullLogger.Instance);

        set.Published.Should().HaveCount(3, "a saturated retention never retires a key");
    }

    [Fact]
    public void Build_keeps_every_key_published_while_the_oldest_key_signs_under_the_warning()
    {
        var oldest = CreateRsaSourceKey("oldest", notBefore: Now.AddHours(-3));
        var newer = CreateRsaSourceKey("newer", notBefore: Now.AddHours(-1));

        var set = Build(oldest, newer);

        set.Published.Select(k => k.SourceId).Should().Equal(oldest.Id, newer.Id);
    }

    [Fact]
    public void Build_publishes_keys_oldest_first_whatever_order_the_source_lists_them_in()
    {
        var next = CreateRsaSourceKey("next", notBefore: Now.AddHours(-1));
        var current = CreateRsaSourceKey("current", notBefore: SigningInsideRetention);
        var previous = CreateRsaSourceKey("previous", notBefore: Now.AddDays(-10));

        var set = Build(next, current, previous);

        set.Published.Select(k => k.SourceId).Should().Equal(previous.Id, current.Id, next.Id);
    }

    [Fact]
    public void Build_advertised_algorithms_are_the_distinct_published_algorithms_in_ascending_order()
    {
        var previous = CreateEcSourceKey("previous", ECCurve.NamedCurves.nistP521, SigningAlgorithm.ES512, Now.AddDays(-10));
        var current = CreateRsaSourceKey("current", algorithm: SigningAlgorithm.RS256, notBefore: SigningInsideRetention);
        var next = CreateEcSourceKey("next", ECCurve.NamedCurves.nistP256, SigningAlgorithm.ES256, Now.AddHours(-1));

        var set = Build(previous, current, next);

        set.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256, SigningAlgorithm.ES256, SigningAlgorithm.ES512);
    }

    [Fact]
    public void Build_advertised_algorithms_deduplicates_when_multiple_keys_share_an_algorithm()
    {
        var previous = CreateRsaSourceKey("previous", notBefore: Now.AddDays(-10));
        var current = CreateRsaSourceKey("current", notBefore: SigningInsideRetention);

        var set = Build(previous, current);

        set.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256);
    }

    [Fact]
    public void Build_derives_Kid_as_the_RFC7638_thumbprint_of_the_public_key()
    {
        var current = CreateRsaSourceKey("current");

        var set = Build(current);

        set.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(current.PublicKey.RsaPublicParameters!.Value));
    }

    // ── Validation: the list and its dates ───────────────────────────────────────────────────────

    [Fact]
    public void Build_throws_ArgumentNullException_when_keys_is_null()
    {
        var act = () => SigningKeySetBuilder.Build(null!, Now, Options(), NullLogger.Instance);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Build_fails_with_no_keys_when_the_source_lists_none()
    {
        var act = () => Build();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_keys");
    }

    [Fact]
    public void Build_fails_with_null_key_when_the_source_lists_a_null()
    {
        var act = () => Build(CreateRsaSourceKey("current", notBefore: Now.AddDays(-2)), null!);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.null_key");
    }

    [Fact]
    public void Build_fails_with_undated_key_when_two_keys_are_undated()
    {
        var act = () => Build(CreateRsaSourceKey("a"), CreateRsaSourceKey("b"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.undated_key");
    }

    [Fact]
    public void Build_fails_with_undated_key_when_one_of_two_keys_is_undated()
    {
        var act = () => Build(CreateRsaSourceKey("dated", notBefore: Now.AddDays(-2)), CreateRsaSourceKey("undated"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.undated_key" && f.Message.Contains("'undated'"));
    }

    [Fact]
    public void Build_fails_with_invalid_validity_window_when_a_key_expires_before_it_becomes_valid()
    {
        var act = () => Build(CreateRsaSourceKey("current", notBefore: Now.AddDays(-1), expiresAt: Now.AddDays(-2)));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.invalid_validity_window");
    }

    // ── Validation: source id ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Build_throws_when_a_source_id_is_empty_or_whitespace(string emptyId)
    {
        var current = CreateRsaSourceKey(emptyId);
        var act = () => Build(current);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.empty_key_id");
    }

    [Fact]
    public void Build_throws_when_two_keys_share_a_source_id()
    {
        var current = CreateRsaSourceKey("dup", notBefore: Now.AddDays(-2));
        var next = CreateRsaSourceKey("dup", notBefore: Now.AddHours(-1));
        var act = () => Build(current, next);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.duplicate_key_id");
    }

    // ── Validation: kid ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_two_distinct_source_ids_derive_the_same_kid()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));

        var previous = new SourceKey(new SourceKeyId("previous"), SigningAlgorithm.RS256, publicKey, Now.AddDays(-10));
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey, Now.AddDays(-2));

        var act = () => Build(previous, current);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.duplicate_kid");
    }

    // ── Validation: algorithm/key-type compatibility ────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_an_RSA_algorithm_is_declared_over_an_EC_public_key()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey);
        var act = () => Build(current);

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
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey);
        var act = () => Build(current);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Message.Contains("'current'"));
    }

    [Fact]
    public void Build_throws_when_an_EC_algorithm_is_declared_over_an_RSA_public_key()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.ES256, publicKey);
        var act = () => Build(current);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
    }

    [Fact]
    public void Build_throws_when_the_EC_algorithm_does_not_match_the_key_curve()
    {
        // ES256 requires P-256; the key is P-384.
        var current = CreateEcSourceKey("current", ECCurve.NamedCurves.nistP384, SigningAlgorithm.ES256);
        var act = () => Build(current);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.ec_curve_algorithm_mismatch");
    }

    // ── Public key material is immutable once built ─────────────────────────────────────────────

    [Fact]
    public void Build_result_is_immune_to_mutating_every_reachable_RSA_public_key_accessor()
    {
        var current = CreateRsaSourceKey("current");
        var set = Build(current);
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
        var set = Build(current);
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
        var set = Build(current);

        set.SigningKey.PublicKey.Should().NotBeSameAs(current.PublicKey);
    }

    // ── Validation: undefined algorithm ──────────────────────────────────────────────────────────

    [Fact]
    public void Build_throws_when_the_declared_algorithm_is_not_a_defined_SigningAlgorithm_member()
    {
        var current = CreateRsaSourceKey("current", algorithm: (SigningAlgorithm)999);
        var act = () => Build(current);

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
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.ES256, publicKey);
        var act = () => Build(current);

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
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey);
        var act = () => Build(current);

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
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey);
        var act = () => Build(current);

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
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.RS256, publicKey);
        var act = () => Build(current);

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
        var current = new SourceKey(new SourceKeyId("current"), SigningAlgorithm.ES256, publicKey);
        var act = () => Build(current);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.ec_unsupported_curve");
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

        var act = () => SigningKeySetBuilder.ValidateKeyStrength(new SourceKey(new SourceKeyId("test-key"), SigningAlgorithm.RS256, publicKey));

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

        var act = () => SigningKeySetBuilder.ValidateKeyStrength(new SourceKey(new SourceKeyId("test-key"), SigningAlgorithm.RS256, publicKey));

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

        var act = () => SigningKeySetBuilder.ValidateKeyAlgorithmCompatibility(new SourceKey(new SourceKeyId("test-key"), algorithm, publicKey));

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateKeyAlgorithmCompatibility_rejects_an_EC_key_whose_curve_does_not_match_the_algorithm()
    {
        // ES256 requires P-256 (RFC 7518 §3.4); a P-384 key under ES256 is a misconfiguration,
        // reported with the stable failure code rather than accepted or crashed on.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));

        var act = () => SigningKeySetBuilder.ValidateKeyAlgorithmCompatibility(new SourceKey(new SourceKeyId("test-key"), SigningAlgorithm.ES256, publicKey));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures[0].Code.Should().Be("signing.ec_curve_algorithm_mismatch");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static SigningKeyOptions Options() => new() { LeadTime = LeadTime, RetainRetiredKeysFor = Retention };

    private static SigningKeySet Build(params SourceKey[] keys) => SigningKeySetBuilder.Build(keys, Now, Options(), NullLogger.Instance);

    private static SigningKeySet Build(CapturingSanitizingLogger<SigningKeyRing> logger, params SourceKey[] keys)
        => SigningKeySetBuilder.Build(keys, Now, Options(), logger);

    private static SourceKey CreateRsaSourceKey(
        string id, int keySize = 2048, SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        DateTimeOffset? notBefore = null, DateTimeOffset? expiresAt = null)
    {
        using var rsa = RSA.Create(keySize);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        return new SourceKey(new SourceKeyId(id), algorithm, publicKey, notBefore, expiresAt ?? Now.AddDays(90));
    }

    private static SourceKey CreateEcSourceKey(string id, ECCurve curve, SigningAlgorithm algorithm, DateTimeOffset? notBefore = null)
    {
        using var ec = ECDsa.Create(curve);
        var publicKey = PublicKeyParameters.FromEc(ec.ExportParameters(false));
        return new SourceKey(new SourceKeyId(id), algorithm, publicKey, notBefore, Now.AddDays(90));
    }
}
