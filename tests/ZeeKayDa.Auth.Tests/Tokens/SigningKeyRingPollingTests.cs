using System.Security.Cryptography;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeyRing"/> re-reading its source every
/// <see cref="SigningKeyOptions.RefreshInterval"/>: what each kind of read does to the key set, to
/// signing, to keys set aside, and to the signers of keys no longer listed.
/// </summary>
public sealed class SigningKeyRingPollingTests
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly TimeSpan RefreshInterval = TestSigningKeys.Options.RefreshInterval;

    [Fact]
    public async Task The_source_is_read_again_every_refresh_interval()
    {
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock);

        await ReadAgainAsync(ring, clock);
        await ReadAgainAsync(ring, clock);

        listing.Reads.Should().Be(3);
    }

    [Fact]
    public async Task A_key_listed_after_startup_is_published_at_the_next_read()
    {
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [.. listing.Pairs, TestSigningKeys.Pair("next", notBefore: Epoch)];
        await ReadAgainAsync(ring, clock);

        ring.Current.Published.Select(key => key.SourceId.Value).Should().Equal("current", "next");
        ring.Current.SigningKey!.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task A_failed_read_keeps_the_last_list_logs_an_Error_and_makes_the_health_check_Degraded()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock, logger);
        var before = ring.Current;

        listing.ReadFailure = new HttpRequestException("simulated: vault unreachable");
        await ReadAgainAsync(ring, clock);

        ring.Current.Published.Should().Equal(before.Published);
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
        logger.Entries.Should().ContainSingle(entry => entry.Level == LogLevel.Error)
            .Which.Message.Should().Contain(typeof(HttpRequestException).FullName);
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public async Task A_read_that_does_not_complete_within_a_minute_counts_as_failed_and_keeps_the_last_list()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock, logger);

        listing.ReadHangs = true;
        clock.Advance(RefreshInterval);
        clock.Advance(TimeSpan.FromMinutes(1));
        await ring.LastTransition;

        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
        logger.Entries.Should().ContainSingle(entry => entry.Level == LogLevel.Error)
            .Which.Message.Should().Contain("did not complete within");
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public async Task A_read_still_running_after_its_deadline_is_not_started_again_at_the_next_read()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock, logger);
        listing.ReadHangs = true;
        clock.Advance(RefreshInterval);
        clock.Advance(TimeSpan.FromMinutes(1));
        await ring.LastTransition;

        await ReadAgainAsync(ring, clock);

        listing.Reads.Should().BeLessThanOrEqualTo(2, "the startup read, then at most the one still running");
        logger.Entries.Should().Contain(entry => entry.Level == LogLevel.Error && entry.Message.Contains("has not completed"));
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task A_good_read_after_a_failed_one_makes_the_health_check_Healthy_again()
    {
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock);
        listing.ReadFailure = new HttpRequestException("simulated: vault unreachable");
        await ReadAgainAsync(ring, clock);

        listing.ReadFailure = null;
        await ReadAgainAsync(ring, clock);

        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task A_read_listing_no_keys_stops_signing_publishes_nothing_and_makes_the_health_check_Unhealthy()
    {
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [];
        await ReadAgainAsync(ring, clock);

        ring.Current.SigningKey.Should().BeNull();
        ring.Current.Published.Should().BeEmpty();
        ring.Current.Algorithm.Should().Be(SigningAlgorithm.ES256);
        await FluentActions.Awaiting(() => SignAsync(ring)).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*signing.no_keys*");
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task A_read_listing_duplicate_source_ids_stops_signing()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [current, TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-80))];
        await ReadAgainAsync(ring, clock);

        ring.Current.SigningKey.Should().BeNull();
        ring.Current.Published.Should().BeEmpty();
    }

    [Fact]
    public async Task A_key_pair_listed_under_two_source_ids_is_logged_once_at_Information_naming_both()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(10));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock, logger);

        listing.Pairs = [current, TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90))];
        await ReadAgainAsync(ring, clock);
        await ReadAgainAsync(ring, clock);

        var merge = logger.Entries.Where(entry => entry.Message.Contains("share one key pair"))
            .Should().ContainSingle("a key listed twice at one read is logged once, not at every read").Subject;
        merge.Level.Should().Be(LogLevel.Information);
        merge.Message.Should().Contain("keys current, renewed share").And.Contain("opens through renewed");
        logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task A_renewal_reusing_the_signing_key_pair_signs_through_a_signer_opened_for_the_renewal()
    {
        // A remote signer is bound to the entry it was opened through, which may stop signing at its own expiry.
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(10));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [current, TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90))];
        await ReadAgainAsync(ring, clock);

        listing.SignersOpened.Select(id => id.Value).Should().Equal("current", "renewed");
        listing.SignedBy.Clear();
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("renewed");
        listing.SignedBy.Select(id => id.Value).Should().Equal(["renewed"], "the signer opened through the original entry signs no more");
    }

    [Fact]
    public async Task The_health_check_is_Degraded_while_a_renewal_over_the_signing_key_pair_is_still_opening()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(100));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock);
        listing.SignerGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        listing.SignerRequested = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        listing.Pairs = [current, TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(200))];
        clock.Advance(RefreshInterval);
        await listing.SignerRequested.Task;

        var opening = await HealthAsync(ring, clock);
        opening.Status.Should().Be(HealthStatus.Degraded);
        opening.Description.Should().NotContain("renewed").And.NotContain("current");

        listing.SignerGate.SetResult();
        await ring.LastTransition;
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task A_renewal_whose_signer_fails_leaves_the_earlier_signer_signing_and_is_tried_again_at_the_next_read()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(10));
        var renewal = TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock, logger);

        listing.Pairs = [current, TestSigningKeys.Mismatched(renewal)];
        await ReadAgainAsync(ring, clock);

        listing.SignedBy.Clear();
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
        listing.SignedBy.Select(id => id.Value).Should().Equal("current");
        logger.Warnings.Should().ContainSingle().Which.Should().Contain("signs on");
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Degraded);

        listing.Pairs = [current, renewal];
        await ReadAgainAsync(ring, clock);

        listing.SignersOpened.Select(id => id.Value).Should().Equal("current", "renewed", "renewed");
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("renewed");
    }

    [Fact]
    public async Task A_key_pair_whose_signer_moves_to_another_of_its_source_ids_is_logged_again()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(10));
        var listing = new TestSigningKeys.Listing(current, TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90)));
        using var ring = TestSigningKeys.Ring(listing, clock, logger);

        listing.Pairs = [TestSigningKeys.Renewal(current, "current", Epoch.AddDays(-90), Epoch.AddDays(200)), listing.Pairs[1]];
        await ReadAgainAsync(ring, clock);

        logger.Entries.Where(entry => entry.Message.Contains("share one key pair")).Select(entry => entry.Message)
            .Should().SatisfyRespectively(
                atStartup => atStartup.Should().Contain("opens through renewed"),
                atTheRead => atTheRead.Should().Contain("opens through current"));
    }

    [Fact]
    public async Task The_health_check_is_Unhealthy_once_the_earlier_entry_expires_while_its_renewal_keeps_failing()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch + RefreshInterval + RefreshInterval / 2);
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [current, TestSigningKeys.Mismatched(TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90)))];
        await ReadAgainAsync(ring, clock);
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Degraded);

        await ReadAgainAsync(ring, clock);

        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Unhealthy, "the signer still signing is bound to an entry that has expired");
    }

    [Fact]
    public async Task A_signing_entry_replaced_by_a_renewal_of_its_key_pair_stops_signing_and_does_not_sign_on_when_the_renewal_fails()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(10));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [TestSigningKeys.Mismatched(TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90)))];
        await ReadAgainAsync(ring, clock);

        ring.Current.SigningKey.Should().BeNull("the source no longer lists the entry whose signer was signing");
        await FluentActions.Awaiting(() => SignAsync(ring)).Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task The_earlier_entry_s_signer_is_disposed_at_the_read_after_the_renewal_takes_over()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(10));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [current, TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90))];
        await ReadAgainAsync(ring, clock);
        listing.SignersDisposed.Should().BeEmpty("one read's grace lets a sign call already holding it finish");

        await ReadAgainAsync(ring, clock);

        listing.SignersDisposed.Select(id => id.Value).Should().Equal("current");
    }

    [Fact]
    public async Task A_key_pair_listed_under_a_further_source_id_is_logged_again()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(10));
        var listing = new TestSigningKeys.Listing(current, TestSigningKeys.Renewal(current, "renewed", Epoch, Epoch.AddDays(90)));
        using var ring = TestSigningKeys.Ring(listing, clock, logger);

        listing.Pairs = [.. listing.Pairs, TestSigningKeys.Renewal(current, "renewed-again", Epoch, Epoch.AddDays(180))];
        await ReadAgainAsync(ring, clock);

        logger.Entries.Where(entry => entry.Message.Contains("share one key pair")).Select(entry => entry.Message)
            .Should().SatisfyRespectively(
                atStartup => atStartup.Should().Contain("keys current, renewed share"),
                atTheRead => atTheRead.Should().Contain("keys current, renewed, renewed-again share"));
    }

    [Fact]
    public async Task A_read_whose_key_due_to_sign_now_has_bad_material_stops_signing()
    {
        // Rather than letting the older key sign on: someone able to write one bad key must not be
        // able to freeze the set it was meant to replace.
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [.. listing.Pairs, WrongCurve("replacement", notBefore: Epoch.AddDays(-10))];
        await ReadAgainAsync(ring, clock);

        ring.Current.SigningKey.Should().BeNull();
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task A_read_with_a_bad_staged_key_drops_it_with_a_Warning_and_signing_carries_on()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock, logger);

        listing.Pairs = [.. listing.Pairs, WrongCurve("staged", notBefore: Epoch)];
        await ReadAgainAsync(ring, clock);
        await ReadAgainAsync(ring, clock);

        ring.Current.SigningKey!.SourceId.Value.Should().Be("current");
        ring.Current.Published.Select(key => key.SourceId.Value).Should().Equal("current");
        logger.Entries.Where(entry => entry.Level == LogLevel.Warning && entry.Message.Contains("staged"))
            .Should().ContainSingle("a key dropped at one read is warned about once, not at every read");
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public async Task A_bad_staged_key_stops_signing_at_the_first_read_after_it_comes_due()
    {
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(
            TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), WrongCurve("staged", notBefore: Epoch));
        using var ring = TestSigningKeys.Ring(listing, clock);

        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime);
        await ring.LastTransition;

        ring.Current.SigningKey.Should().BeNull();
    }

    [Fact]
    public async Task Signing_resumes_when_a_later_read_lists_usable_keys_again()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90));
        var listing = new TestSigningKeys.Listing(current);
        using var ring = TestSigningKeys.Ring(listing, clock);
        listing.Pairs = [];
        await ReadAgainAsync(ring, clock);

        var replacement = TestSigningKeys.Pair("replacement", notBefore: clock.GetUtcNow());
        listing.Pairs = [replacement];
        await ReadAgainAsync(ring, clock);

        var outcome = await SignAsync(ring);
        outcome.Key.SourceId.Value.Should().Be("replacement");
        ring.Current.Published.Select(key => key.SourceId.Value).Should().Equal("replacement");
        (await HealthAsync(ring, clock)).Status.Should().NotBe(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task A_signing_key_no_longer_listed_stops_signing_and_is_unpublished_before_its_successor_s_signer_opens()
    {
        var clock = new FakeTimeProvider(Epoch);
        var previous = TestSigningKeys.Pair("previous", notBefore: Epoch.AddDays(-90));
        var listing = new TestSigningKeys.Listing(previous, TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-30)));
        using var ring = TestSigningKeys.Ring(listing, clock);
        listing.SignerGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        listing.SignerRequested = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        listing.Pairs = [previous];
        clock.Advance(RefreshInterval);
        await listing.SignerRequested.Task;

        ring.Current.SigningKey.Should().BeNull();
        ring.Current.Published.Select(key => key.SourceId.Value).Should().Equal("previous");
        await FluentActions.Awaiting(() => SignAsync(ring)).Should().ThrowAsync<InvalidOperationException>();
        (await HealthAsync(ring, clock)).Status.Should().Be(HealthStatus.Unhealthy);

        listing.SignerGate.SetResult();
        await ring.LastTransition;
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("previous");
    }

    [Fact]
    public async Task A_read_publishes_its_keys_at_once_while_the_handover_it_starts_is_still_opening()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-30));
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("revoked", notBefore: Epoch.AddDays(-90)), current);
        using var ring = TestSigningKeys.Ring(listing, clock);
        listing.SignerGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        listing.SignerRequested = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        listing.Pairs = [current, TestSigningKeys.Pair("successor", notBefore: Epoch.AddDays(-10))];
        clock.Advance(RefreshInterval);
        await listing.SignerRequested.Task;

        ring.Current.Published.Select(key => key.SourceId.Value).Should().Equal("current", "successor");
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current", "it signs on until the successor's signer opens");

        listing.SignerGate.SetResult();
        await ring.LastTransition;
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("successor");
    }

    [Fact]
    public async Task The_health_check_is_Unhealthy_while_signing_resumes_until_the_handover_completes()
    {
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock);
        listing.Pairs = [];
        await ReadAgainAsync(ring, clock);
        listing.SignerGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        listing.SignerRequested = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        listing.Pairs = [TestSigningKeys.Pair("replacement", notBefore: clock.GetUtcNow())];
        clock.Advance(RefreshInterval);
        await listing.SignerRequested.Task;

        var resuming = await HealthAsync(ring, clock);
        resuming.Status.Should().Be(HealthStatus.Unhealthy);
        resuming.Data.Values.OfType<SigningKeyExpiryStatus>().Should().ContainSingle()
            .Which.IsSigningKey.Should().BeFalse("the published key is reported, but nothing signs yet");
        listing.SignerGate.SetResult();
        await ring.LastTransition;
        (await HealthAsync(ring, clock)).Status.Should().NotBe(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task A_signing_key_no_longer_listed_hands_signing_over_to_a_listed_key_at_the_next_read()
    {
        var clock = new FakeTimeProvider(Epoch);
        var previous = TestSigningKeys.Pair("previous", notBefore: Epoch.AddDays(-90));
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-30));
        var listing = new TestSigningKeys.Listing(previous, current);
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Pairs = [previous];
        await ReadAgainAsync(ring, clock);

        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("previous");
        ring.Current.Published.Select(key => key.SourceId.Value).Should().Equal("previous");
    }

    [Fact]
    public async Task A_set_aside_key_is_tried_again_at_the_next_read_and_takes_over_once_fixed()
    {
        var clock = new FakeTimeProvider(Epoch);
        var successor = TestSigningKeys.Pair("successor", notBefore: Epoch);
        var listing = new TestSigningKeys.Listing(
            TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Mismatched(successor));
        using var ring = TestSigningKeys.Ring(listing, clock);
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime);
        await ring.LastTransition;
        ring.TimelineOrNull!.SetAside.Should().ContainSingle();

        listing.Pairs = [listing.Pairs[0], successor];
        await ReadAgainAsync(ring, clock);

        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("successor");
        ring.TimelineOrNull!.SetAside.Should().BeEmpty();
    }

    [Fact]
    public async Task A_set_aside_key_fixed_only_after_the_key_it_replaces_is_superseded_never_takes_over()
    {
        // By then the rules have dropped the older key elsewhere; taking over now would drop it here
        // too, while tokens it signed moments ago are still live.
        var clock = new FakeTimeProvider(Epoch);
        var successor = TestSigningKeys.Pair("successor", notBefore: Epoch);
        var listing = new TestSigningKeys.Listing(
            TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Mismatched(successor));
        using var ring = TestSigningKeys.Ring(listing, clock);
        listing.ReadFailure = new HttpRequestException("simulated: the fix cannot be read yet");
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime);
        await ring.LastTransition;
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime + TestSigningKeys.Options.RetainRetiredKeysFor!.Value);
        await ring.LastTransition;

        listing.ReadFailure = null;
        listing.Pairs = [listing.Pairs[0], successor];
        await ReadAgainAsync(ring, clock);

        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
        ring.TimelineOrNull!.SetAside.Should().ContainSingle().Which.SourceId.Value.Should().Be("successor");
    }

    [Fact]
    public async Task A_failed_key_too_late_to_take_over_stays_set_aside_after_a_read_that_omitted_it()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90));
        var successor = TestSigningKeys.Pair("successor", notBefore: Epoch);
        var listing = new TestSigningKeys.Listing(current, TestSigningKeys.Mismatched(successor));
        using var ring = TestSigningKeys.Ring(listing, clock);
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime);
        await ring.LastTransition;
        listing.Pairs = [current];
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime + TestSigningKeys.Options.RetainRetiredKeysFor!.Value);
        await ring.LastTransition;

        listing.Pairs = [current, successor];
        await ReadAgainAsync(ring, clock);

        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task A_failed_key_whose_cutoff_passes_while_the_source_is_read_stays_set_aside()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90));
        var successor = TestSigningKeys.Pair("successor", notBefore: Epoch);
        var listing = new TestSigningKeys.Listing(current, TestSigningKeys.Mismatched(successor));
        using var ring = TestSigningKeys.Ring(listing, clock);
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime);
        await ring.LastTransition;

        var cutoff = Epoch + TestSigningKeys.Options.LeadTime + TestSigningKeys.Options.RetainRetiredKeysFor!.Value;
        listing.Pairs = [current, successor];
        listing.DuringRead = () => clock.SetUtcNow(cutoff + TimeSpan.FromSeconds(1));
        clock.SetUtcNow(cutoff - TimeSpan.FromSeconds(1));
        await ring.LastTransition;

        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task The_signer_of_a_key_no_longer_listed_is_disposed_at_the_second_read_without_it_not_the_first()
    {
        var clock = new FakeTimeProvider(Epoch);
        var disposed = new List<string>();
        var previous = TestSigningKeys.Pair("previous", notBefore: Epoch.AddDays(-90));
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-30));
        var listing = new TestSigningKeys.Listing(previous, current);
        using var ring = TestSigningKeys.Ring(
            listing, clock, decorateSigner: signer => new TrackingSigner(signer, () => disposed.Add("signer")));

        listing.Pairs = [previous];
        await ReadAgainAsync(ring, clock);
        disposed.Should().BeEmpty("a sign call that resolved the old signer just before the read may still be using it");

        await ReadAgainAsync(ring, clock);
        disposed.Should().ContainSingle();
    }

    [Fact]
    public async Task A_failed_handover_that_stops_signing_still_gives_the_old_signer_one_read_s_grace()
    {
        var clock = new FakeTimeProvider(Epoch);
        var opened = 0;
        var disposed = new List<string>();
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(
            listing,
            clock,
            decorateSigner: signer =>
            {
                var name = opened++ == 0 ? "current" : "replacement";
                return new TrackingSigner(signer, () => disposed.Add(name));
            });

        listing.Pairs = [TestSigningKeys.Mismatched(TestSigningKeys.Pair("replacement", notBefore: Epoch.AddDays(-10)))];
        await ReadAgainAsync(ring, clock);

        ring.Current.SigningKey.Should().BeNull();
        disposed.Should().NotContain("current");

        await ReadAgainAsync(ring, clock);
        disposed.Should().Contain("current");
    }

    [Fact]
    public async Task The_signer_of_a_key_listed_again_before_the_second_read_is_kept()
    {
        var clock = new FakeTimeProvider(Epoch);
        var disposed = 0;
        var previous = TestSigningKeys.Pair("previous", notBefore: Epoch.AddDays(-90));
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-30));
        var listing = new TestSigningKeys.Listing(previous, current);
        using var ring = TestSigningKeys.Ring(
            listing, clock, decorateSigner: signer => new TrackingSigner(signer, () => disposed++));
        listing.Pairs = [];
        await ReadAgainAsync(ring, clock);

        listing.Pairs = [previous, current];
        await ReadAgainAsync(ring, clock);
        await ReadAgainAsync(ring, clock);

        disposed.Should().Be(0);
        (await SignAsync(ring)).Key.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task The_ring_keeps_signing_under_the_algorithm_it_read_at_startup_when_the_source_s_changes()
    {
        var clock = new FakeTimeProvider(Epoch);
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        using var ring = TestSigningKeys.Ring(listing, clock);

        listing.Algorithm = SigningAlgorithm.ES384;
        await ReadAgainAsync(ring, clock);

        ring.Current.Algorithm.Should().Be(SigningAlgorithm.ES256);
        (await SignAsync(ring)).Key.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static async Task ReadAgainAsync(SigningKeyRing ring, FakeTimeProvider clock)
    {
        clock.Advance(RefreshInterval);
        await ring.LastTransition;
    }

    private static Task<SigningOutcome> SignAsync(SigningKeyRing ring) =>
        ring.SignAsync(0, static (_, _) => "payload"u8.ToArray(), TestContext.Current.CancellationToken);

    private static Task<HealthCheckResult> HealthAsync(SigningKeyRing ring, TimeProvider clock) =>
        new SigningKeyExpiryHealthCheck(
                ring, clock, Microsoft.Extensions.Options.Options.Create(new SigningKeyExpiryHealthCheckOptions()))
            .CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

    /// <summary>A P-384 key, which an ES256 source cannot sign with, so the ring drops it.</summary>
    private static TestSigningKeys.KeyPair WrongCurve(string id, DateTimeOffset notBefore)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        return new TestSigningKeys.KeyPair(
            TestSigningKeys.SourceKey(id, ec, notBefore), ec.ExportParameters(includePrivateParameters: true));
    }

    private sealed class TrackingSigner(ISigner inner, Action onDispose) : ISigner
    {
        public Task<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            inner.SignAsync(signingInput, cancellationToken);

        public void Dispose()
        {
            onDispose();
            inner.Dispose();
        }
    }
}
