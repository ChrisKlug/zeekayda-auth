using System.Linq;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeyRotationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultRetirementWindow = TimeSpan.FromHours(1);

    private static RotationKey Key(string id, DateTimeOffset activatesAt, DateTimeOffset? expiresAt = null) =>
        new(id, activatesAt, expiresAt ?? activatesAt + TimeSpan.FromDays(365));

    // ── Bootstrap exemption ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void SelectActiveKey_single_key_activates_immediately_regardless_of_future_ActivatesAt()
    {
        var key = Key("AAA", activatesAt: T0 + TimeSpan.FromDays(30));
        var timeline = SigningKeyRotation.BuildActivationTimeline([key]);

        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0);

        active.Should().NotBeNull();
        active!.Value.Key.Id.Should().Be("AAA");
    }

    [Fact]
    public void SelectActiveKey_single_expired_key_fails_closed()
    {
        var key = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(400), expiresAt: T0 - TimeSpan.FromDays(1));
        var timeline = SigningKeyRotation.BuildActivationTimeline([key]);

        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0);

        active.Should().BeNull("the bootstrap exemption covers activation timing only, not expiry");
    }

    // ── Two-key rotation ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void SelectActiveKey_two_keys_the_one_whose_ActivatesAt_has_arrived_and_is_most_recent_is_active()
    {
        var predecessor = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(30));
        var successor = Key("BBB", activatesAt: T0 - TimeSpan.FromDays(1));
        var timeline = SigningKeyRotation.BuildActivationTimeline([predecessor, successor]);

        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0);

        active!.Value.Key.Id.Should().Be("BBB");
    }

    [Fact]
    public void SelectActiveKey_flips_to_successor_once_its_ActivatesAt_arrives()
    {
        var predecessor = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(30));
        var successorActivatesAt = T0 + TimeSpan.FromDays(1);
        var successor = Key("BBB", activatesAt: successorActivatesAt);
        var timeline = SigningKeyRotation.BuildActivationTimeline([predecessor, successor]);

        SigningKeyRotation.SelectActiveKey(timeline, now: T0)!.Value.Key.Id.Should().Be("AAA", "successor has not activated yet");
        SigningKeyRotation.SelectActiveKey(timeline, now: successorActivatesAt)!.Value.Key.Id.Should().Be("BBB", "successor's ActivatesAt has now arrived");
    }

    [Fact]
    public void SelectIncludedKeys_includes_both_when_successor_is_not_yet_active()
    {
        var predecessor = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(30));
        var successor = Key("BBB", activatesAt: T0 + TimeSpan.FromDays(1));
        var timeline = SigningKeyRotation.BuildActivationTimeline([predecessor, successor]);
        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0)!.Value;

        var included = SigningKeyRotation.SelectIncludedKeys(timeline, active, now: T0, DefaultRetirementWindow);

        included.Should().HaveCount(2, "both keys must appear in JWKS during the overlap window");
        included[0].Key.Id.Should().Be("AAA", "the active key is always first");
        included.Should().Contain(e => e.Key.Id == "BBB");
    }

    [Fact]
    public void SelectIncludedKeys_retirement_of_predecessor_is_measured_from_successors_ActivatesAt()
    {
        var predecessor = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(30));
        var successorActivatesAt = T0 - TimeSpan.FromMinutes(30);
        var successor = Key("BBB", activatesAt: successorActivatesAt);
        var timeline = SigningKeyRotation.BuildActivationTimeline([predecessor, successor]);
        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0)!.Value;
        active.Key.Id.Should().Be("BBB");

        // Predecessor's retirement clock started at successor's ActivatesAt (30 min ago), not at
        // "now" and not at the predecessor's own ActivatesAt.
        var stillWithinWindow = SigningKeyRotation.SelectIncludedKeys(timeline, active, now: T0, retirementWindow: TimeSpan.FromHours(1));
        stillWithinWindow.Should().Contain(e => e.Key.Id == "AAA", "30 minutes since retirement is within a 1-hour window");

        var pastWindow = SigningKeyRotation.SelectIncludedKeys(timeline, active, now: T0, retirementWindow: TimeSpan.FromMinutes(10));
        pastWindow.Should().NotContain(e => e.Key.Id == "AAA", "30 minutes since retirement exceeds a 10-minute window");
    }

    [Fact]
    public void SelectIncludedKeys_still_includes_predecessor_exactly_at_the_retirement_window_boundary()
    {
        var successorActivatesAt = T0 - TimeSpan.FromHours(1);
        var predecessor = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(30));
        var successor = Key("BBB", activatesAt: successorActivatesAt);
        var timeline = SigningKeyRotation.BuildActivationTimeline([predecessor, successor]);
        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0)!.Value;

        var included = SigningKeyRotation.SelectIncludedKeys(timeline, active, now: T0, retirementWindow: TimeSpan.FromHours(1));

        included.Should().Contain(e => e.Key.Id == "AAA", "exactly at the boundary is still within the window (<=)");
    }

    [Fact]
    public void A_key_whose_ExpiresAt_precedes_its_own_ActivatesAt_is_never_a_real_successor()
    {
        // A malformed/degenerate registration: "BBB" would chronologically activate before "CCC"
        // but is already past its own ExpiresAt at that very instant, so it can never win
        // SelectActiveKey's selection - it must not gate "AAA"'s retirement.
        var predecessor = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(30));
        var neverReallyActive = new RotationKey(
            "BBB", ActivatesAt: T0 - TimeSpan.FromDays(10), ExpiresAt: T0 - TimeSpan.FromDays(11));
        var realSuccessor = Key("CCC", activatesAt: T0 - TimeSpan.FromDays(1));
        var timeline = SigningKeyRotation.BuildActivationTimeline([predecessor, neverReallyActive, realSuccessor]);

        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0)!.Value;
        active.Key.Id.Should().Be("CCC");

        var aaaEntry = timeline.Single(e => e.Key.Id == "AAA");
        aaaEntry.RetiredAt.Should().Be(realSuccessor.ActivatesAt,
            "AAA's retirement must be anchored to CCC's ActivatesAt, not BBB's, since BBB could never have actually won the selection");
    }

    [Fact]
    public void SelectActiveKey_returns_null_when_all_keys_are_not_yet_active()
    {
        var a = Key("AAA", activatesAt: T0 + TimeSpan.FromDays(1));
        var b = Key("BBB", activatesAt: T0 + TimeSpan.FromDays(2));
        var timeline = SigningKeyRotation.BuildActivationTimeline([a, b]);

        var active = SigningKeyRotation.SelectActiveKey(timeline, now: T0);

        active.Should().BeNull("2+ keys with none yet activated must fail closed, not silently pick one");
    }

    // ── HasTooSoonPendingActivation ───────────────────────────────────────────────────────────────

    [Fact]
    public void HasTooSoonPendingActivation_true_when_soonest_pending_ActivatesAt_is_closer_than_RefreshInterval()
    {
        var active = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(1));
        var pending = Key("BBB", activatesAt: T0 + TimeSpan.FromMinutes(1));
        var timeline = SigningKeyRotation.BuildActivationTimeline([active, pending]);
        var activeEntry = timeline.Single(e => e.Key.Id == "AAA");

        var hasWarning = SigningKeyRotation.HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out var soonest);

        hasWarning.Should().BeTrue();
        soonest!.Value.Key.Id.Should().Be("BBB");
    }

    [Fact]
    public void HasTooSoonPendingActivation_false_when_soonest_pending_ActivatesAt_is_RefreshInterval_or_further_away()
    {
        var active = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(1));
        var pending = Key("BBB", activatesAt: T0 + DefaultRefreshInterval);
        var timeline = SigningKeyRotation.BuildActivationTimeline([active, pending]);
        var activeEntry = timeline.Single(e => e.Key.Id == "AAA");

        var hasWarning = SigningKeyRotation.HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out _);

        hasWarning.Should().BeFalse("exactly RefreshInterval away is sufficient lead time, not 'too soon'");
    }

    [Fact]
    public void HasTooSoonPendingActivation_false_with_only_one_key()
    {
        var only = Key("AAA", activatesAt: T0 + TimeSpan.FromDays(30));
        var timeline = SigningKeyRotation.BuildActivationTimeline([only]);
        var activeEntry = timeline.Single();

        var hasWarning = SigningKeyRotation.HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out var soonest);

        hasWarning.Should().BeFalse("the warning only applies once a rotation is actually in progress (2+ keys)");
        soonest.Should().BeNull();
    }

    [Fact]
    public void HasTooSoonPendingActivation_false_when_no_key_is_pending()
    {
        var a = Key("AAA", activatesAt: T0 - TimeSpan.FromDays(2));
        var b = Key("BBB", activatesAt: T0 - TimeSpan.FromDays(1));
        var timeline = SigningKeyRotation.BuildActivationTimeline([a, b]);
        var activeEntry = timeline.Single(e => e.Key.Id == "BBB");

        var hasWarning = SigningKeyRotation.HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out var soonest);

        hasWarning.Should().BeFalse();
        soonest.Should().BeNull();
    }
}
