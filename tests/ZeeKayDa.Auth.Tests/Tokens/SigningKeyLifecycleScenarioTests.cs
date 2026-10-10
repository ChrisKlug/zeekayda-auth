using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// The key lifecycle a source author and an operator meet, one scenario per test: what signs, what
/// is published, and what the operator does. Every scenario runs a real ring on a fake clock with a
/// one-day lead time and one day of retention, starting at a fixed instant, and moves the clock to
/// show what happens with no restart.
/// </summary>
public sealed class SigningKeyLifecycleScenarioTests
{
    private static readonly DateTimeOffset Startup = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static readonly TimeSpan LeadTime = TestSigningKeys.Options.LeadTime;

    private static readonly TimeSpan Retention = TestSigningKeys.Options.RetainRetiredKeysFor!.Value;

    private readonly FakeTimeProvider _clock = new(Startup);

    private readonly CapturingSanitizingLogger<SigningKeyRing> _logger = new();

    // ── First deployment ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void First_deployment_with_one_undated_key_signs_with_it_at_once_and_warns_about_nothing()
    {
        using var ring = Ring(TestSigningKeys.Pair("only"));

        SigningId(ring).Should().Be("only");
        _logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void First_deployment_with_one_brand_new_key_signs_with_it_at_once_and_warns()
    {
        using var ring = Ring(TestSigningKeys.Pair("new", notBefore: Startup.AddMinutes(-1)));

        SigningId(ring).Should().Be("new");
        _logger.Warnings.Should().ContainSingle();
    }

    [Fact]
    public void First_deployment_with_a_key_dated_in_the_future_signs_with_it_at_once()
    {
        // NotBefore starts the lead-time clock; no relying party can see it, so it is no validity gate.
        using var ring = Ring(TestSigningKeys.Pair("only", notBefore: Startup.AddDays(3)));

        SigningId(ring).Should().Be("only");
    }

    // ── Normal rotation ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Rotation_staged_successor_is_published_while_the_current_key_keeps_signing()
    {
        using var ring = Ring(Current(), TestSigningKeys.Pair("successor", notBefore: Startup.AddHours(-2)));

        SigningId(ring).Should().Be("current");
        PublishedIds(ring).Should().Equal("current", "successor");
    }

    [Fact]
    public async Task Rotation_the_successor_takes_over_when_its_lead_time_ends_without_a_restart()
    {
        using var ring = Ring(Current(), TestSigningKeys.Pair("successor", notBefore: Startup));

        await AdvanceAsync(ring, LeadTime);

        SigningId(ring).Should().Be("successor");
        PublishedIds(ring).Should().Equal("current", "successor");
        _logger.Entries.Should().Contain(entry => entry.Level == LogLevel.Information && entry.Message.Contains("now signs"));
    }

    [Fact]
    public async Task Rotation_the_predecessor_drops_from_the_key_set_once_its_retention_has_passed()
    {
        using var ring = Ring(Current(), TestSigningKeys.Pair("successor", notBefore: Startup));

        await AdvanceAsync(ring, LeadTime + Retention);

        PublishedIds(ring).Should().Equal("successor");
    }

    [Fact]
    public void Rotation_a_restart_long_after_the_takeover_sees_the_same_set_as_a_process_that_never_restarted()
    {
        using var ring = Ring(Current(), TestSigningKeys.Pair("successor", notBefore: Startup.AddDays(-21)));

        SigningId(ring).Should().Be("successor");
        PublishedIds(ring).Should().Equal("successor");
    }

    [Fact]
    public void Rotation_a_second_rotation_drops_the_key_two_generations_back_once_retention_has_passed()
    {
        using var ring = Ring(
            TestSigningKeys.Pair("first", notBefore: Startup.AddDays(-90)),
            TestSigningKeys.Pair("second", notBefore: Startup.AddDays(-60)),
            TestSigningKeys.Pair("third", notBefore: Startup.AddHours(-36)));

        SigningId(ring).Should().Be("third");
        PublishedIds(ring).Should().Equal("second", "third");
    }

    [Fact]
    public async Task Rotation_a_renewed_certificate_reusing_the_key_pair_keeps_signing()
    {
        var original = TestSigningKeys.Pair("original", notBefore: Startup.AddDays(-80), expiresAt: Startup.AddDays(10));
        var listing = new TestSigningKeys.Listing(original);
        using var ring = TestSigningKeys.Ring(listing, _clock, _logger);
        var kid = ring.Current.SigningKey!.Kid;

        listing.Pairs = [original, TestSigningKeys.Renewal(original, "renewed", notBefore: Startup, expiresAt: Startup.AddDays(100))];
        await AdvanceAsync(ring, TestSigningKeys.Options.RefreshInterval);

        ring.Current.Published.Should().ContainSingle().Which.Kid.Should().Be(kid);

        await AdvanceAsync(ring, TimeSpan.FromDays(10));

        (await SignAsync(ring)).Key.Kid.Should().Be(kid, "the renewal keeps the key pair valid past the original's expiry");
        ring.Current.Published.Should().ContainSingle();
        _logger.Entries.Should().NotContain(entry => entry.Level >= LogLevel.Warning);
    }

    // ── Emergency ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Emergency_removing_a_compromised_key_falls_back_to_its_published_predecessor_with_no_outage()
    {
        // The operator removed the compromised signing key and listed a replacement; the predecessor
        // is still listed, and relying parties already cache it.
        using var ring = Ring(
            TestSigningKeys.Pair("predecessor", notBefore: Startup.AddDays(-60)),
            TestSigningKeys.Pair("replacement", notBefore: Startup.AddMinutes(-15)));

        SigningId(ring).Should().Be("predecessor");
        _logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Emergency_removing_every_compromised_key_lets_the_brand_new_replacement_sign_at_once_and_warns()
    {
        using var ring = Ring(TestSigningKeys.Pair("replacement", notBefore: Startup.AddMinutes(-15)));

        SigningId(ring).Should().Be("replacement");
        PublishedIds(ring).Should().Equal("replacement");
        _logger.Warnings.Should().ContainSingle();
    }

    // ── Expiry ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Expiry_a_key_that_just_expired_never_signs_but_stays_published_for_the_retention()
    {
        using var ring = Ring(
            TestSigningKeys.Pair("expired", notBefore: Startup.AddDays(-90), expiresAt: Startup.AddMinutes(-5)),
            TestSigningKeys.Pair("successor", notBefore: Startup.AddDays(-30)));

        SigningId(ring).Should().Be("successor");
        PublishedIds(ring).Should().Equal("expired", "successor");
    }

    [Fact]
    public async Task Expiry_the_signing_key_expiring_hands_signing_to_the_next_key_even_inside_its_lead_time()
    {
        using var ring = Ring(
            TestSigningKeys.Pair("current", notBefore: Startup.AddDays(-90), expiresAt: Startup.AddHours(1)),
            TestSigningKeys.Pair("successor", notBefore: Startup));

        await AdvanceAsync(ring, TimeSpan.FromHours(1));

        SigningId(ring).Should().Be("successor");
        _logger.Warnings.Should().ContainSingle();
    }

    [Fact]
    public async Task Startup_with_every_key_expired_signs_on_and_is_Unhealthy()
    {
        // A JWK carries no dates (RFC 7517 §4): no relying party can tell the key has expired.
        using var ring = Ring(
            TestSigningKeys.Pair("older", notBefore: Startup.AddDays(-90), expiresAt: Startup.AddMinutes(-10)),
            TestSigningKeys.Pair("last", notBefore: Startup.AddDays(-60), expiresAt: Startup.AddMinutes(-5)));

        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("last");
        _logger.Entries.Should().ContainSingle(entry => entry.Level == LogLevel.Error)
            .Which.Message.Should().Contain("Every listed signing key has expired");
        var health = await new SigningKeyExpiryHealthCheck(ring, _clock, Options.Create(new SigningKeyExpiryHealthCheckOptions()))
            .CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);
        health.Status.Should().Be(HealthStatus.Unhealthy);
    }

    // ── Dates in the future ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Future_a_key_dated_later_is_published_but_does_not_sign_while_an_older_key_can()
    {
        using var ring = Ring(Current(), TestSigningKeys.Pair("future", notBefore: Startup.AddDays(7)));

        SigningId(ring).Should().Be("current");
        PublishedIds(ring).Should().Equal("current", "future");
    }

    // ── Ambiguity ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Ambiguity_two_keys_with_the_same_date_sign_with_the_ordinally_greater_source_id()
    {
        var date = Startup.AddDays(-30);

        using var ring = Ring(TestSigningKeys.Pair("b", notBefore: date), TestSigningKeys.Pair("a", notBefore: date));

        SigningId(ring).Should().Be("b");
    }

    [Fact]
    public void Ambiguity_two_undated_keys_fail_startup_with_undated_key()
    {
        var act = () => Ring(TestSigningKeys.Pair("a"), TestSigningKeys.Pair("b"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.undated_key");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static TestSigningKeys.KeyPair Current() => TestSigningKeys.Pair("current", notBefore: Startup.AddDays(-90));

    private SigningKeyRing Ring(params TestSigningKeys.KeyPair[] keys) => TestSigningKeys.Ring(keys, _clock, _logger);

    private async Task AdvanceAsync(SigningKeyRing ring, TimeSpan by)
    {
        // One step per change instant, as a live clock would pass them.
        var until = _clock.GetUtcNow() + by;
        while (_clock.GetUtcNow() < until)
        {
            var next = ring.TimelineOrNull!.NextChangeAfter(_clock.GetUtcNow());
            _clock.SetUtcNow(next < until ? next : until);
            await ring.LastTransition;
        }
    }

    private static Task<SigningOutcome> SignAsync(SigningKeyRing ring) =>
        ring.SignAsync(0, static (_, _) => "payload"u8.ToArray(), TestContext.Current.CancellationToken);

    private static string SigningId(SigningKeyRing ring) => ring.Current.SigningKey!.SourceId.Value;

    private static string[] PublishedIds(SigningKeyRing ring) => [.. ring.Current.Published.Select(key => key.SourceId.Value)];
}
