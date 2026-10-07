using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// The key lifecycle a source author and an operator meet, one scenario per test: what signs, what
/// is published, and what the operator does. Every scenario runs the real builder with a one-day
/// lead time and ten minutes of retention, at a fixed startup instant.
/// </summary>
public sealed class SigningKeyLifecycleScenarioTests
{
    private static readonly DateTimeOffset Startup = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static readonly SigningKeyOptions Options = new()
    {
        LeadTime = TimeSpan.FromDays(1),
        RetainRetiredKeysFor = TimeSpan.FromMinutes(10),
    };

    // ── First deployment ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void First_deployment_with_one_undated_key_signs_with_it_at_once_and_warns_about_nothing()
    {
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();

        var set = Build(logger, Key("only"));

        set.SigningKey.SourceId.Value.Should().Be("only");
        logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void First_deployment_with_one_brand_new_key_signs_with_it_at_once_and_warns()
    {
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();

        var set = Build(logger, Key("new", notBefore: Startup.AddMinutes(-1)));

        set.SigningKey.SourceId.Value.Should().Be("new");
        logger.Warnings.Should().ContainSingle();
    }

    // ── Normal rotation ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Rotation_staged_successor_is_published_while_the_current_key_keeps_signing()
    {
        var set = Build(Key("current", notBefore: Startup.AddDays(-90)), Key("successor", notBefore: Startup.AddHours(-2)));

        set.SigningKey.SourceId.Value.Should().Be("current");
        Ids(set.Published).Should().Equal("current", "successor");
    }

    [Fact]
    public void Rotation_restart_after_the_lead_time_signs_with_the_successor_and_keeps_the_predecessor_published()
    {
        var set = Build(Key("current", notBefore: Startup.AddDays(-90)), Key("successor", notBefore: Startup.AddDays(-1).AddHours(-1)));

        set.SigningKey.SourceId.Value.Should().Be("successor");
        Ids(set.Published).Should().Equal("current", "successor");
    }

    [Fact]
    public void Rotation_restart_weeks_after_the_lead_time_still_keeps_the_predecessor_published()
    {
        // The predecessor signed until this restart, whenever its successor's lead time ended.
        var set = Build(Key("current", notBefore: Startup.AddDays(-90)), Key("successor", notBefore: Startup.AddDays(-21)));

        set.SigningKey.SourceId.Value.Should().Be("successor");
        Ids(set.Published).Should().Equal("current", "successor");
    }

    [Fact]
    public void Rotation_a_second_rotation_drops_the_key_two_generations_back_once_retention_has_passed()
    {
        var set = Build(
            Key("first", notBefore: Startup.AddDays(-90)),
            Key("second", notBefore: Startup.AddDays(-60)),
            Key("third", notBefore: Startup.AddDays(-30)));

        set.SigningKey.SourceId.Value.Should().Be("third");
        Ids(set.Published).Should().Equal("second", "third");
    }

    // ── Emergency ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Emergency_removing_a_compromised_key_lets_its_brand_new_replacement_sign_at_once_and_warns()
    {
        // The operator removes the compromised key from the source and restarts.
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();

        var set = Build(logger, Key("replacement", notBefore: Startup.AddMinutes(-15)));

        set.SigningKey.SourceId.Value.Should().Be("replacement");
        Ids(set.Published).Should().Equal("replacement");
        logger.Warnings.Should().ContainSingle();
    }

    // ── Expiry ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Expiry_a_key_that_just_expired_never_signs_but_stays_published_for_the_retention()
    {
        var set = Build(
            Key("expired", notBefore: Startup.AddDays(-90), expiresAt: Startup.AddMinutes(-5)),
            Key("successor", notBefore: Startup.AddDays(-30)));

        set.SigningKey.SourceId.Value.Should().Be("successor");
        Ids(set.Published).Should().Equal("expired", "successor");
    }

    [Fact]
    public void Expiry_every_key_expired_fails_startup_with_signing_key_expired()
    {
        var act = () => Build(Key("expired", notBefore: Startup.AddDays(-90), expiresAt: Startup.AddMinutes(-5)));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signing_key_expired");
    }

    // ── Dates in the future ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Future_a_key_valid_up_to_five_minutes_from_now_signs_to_tolerate_clock_skew()
    {
        var set = Build(Key("only", notBefore: Startup.AddMinutes(5)));

        set.SigningKey.SourceId.Value.Should().Be("only");
    }

    [Fact]
    public void Future_a_key_valid_later_than_that_is_published_but_never_signs()
    {
        var set = Build(Key("current", notBefore: Startup.AddDays(-90)), Key("future", notBefore: Startup.AddDays(7)));

        set.SigningKey.SourceId.Value.Should().Be("current");
        Ids(set.Published).Should().Equal("current", "future");
    }

    // ── Ambiguity ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Ambiguity_two_keys_with_the_same_date_sign_with_the_ordinally_greater_source_id()
    {
        var date = Startup.AddDays(-30);

        var set = Build(Key("b", notBefore: date), Key("a", notBefore: date));

        set.SigningKey.SourceId.Value.Should().Be("b");
    }

    [Fact]
    public void Ambiguity_two_undated_keys_fail_startup_with_undated_key()
    {
        var act = () => Build(Key("a"), Key("b"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.undated_key");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static SigningKeySet Build(params SourceKey[] keys) =>
        SigningKeySetBuilder.Build(keys, SigningAlgorithm.ES256, Startup, Options, NullLogger.Instance);

    private static SigningKeySet Build(CapturingSanitizingLogger<SigningKeyRing> logger, params SourceKey[] keys) =>
        SigningKeySetBuilder.Build(keys, SigningAlgorithm.ES256, Startup, Options, logger);

    private static SourceKey Key(string id, DateTimeOffset? notBefore = null, DateTimeOffset? expiresAt = null)
    {
        using var privateKey = TestSigningKeys.PrivateKey(SigningAlgorithm.ES256);
        return TestSigningKeys.SourceKey(id, privateKey, notBefore, expiresAt);
    }

    private static string[] Ids(IEnumerable<SigningKey> keys) => [.. keys.Select(key => key.SourceId.Value)];
}
