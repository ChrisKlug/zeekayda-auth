using static ZeeKayDa.Auth.Windows.WindowsCertificateStoreSigningKeyRotation;

namespace ZeeKayDa.Auth.Windows.Tests;

public sealed class WindowsCertificateStoreSigningKeyRotationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultRetirementWindow = TimeSpan.FromHours(1);

    private static RegisteredCertificateInfo Cert(string thumbprint, DateTimeOffset notBefore, DateTimeOffset? notAfter = null) =>
        new(thumbprint, notBefore, notAfter ?? notBefore + TimeSpan.FromDays(365));

    // ── Bootstrap exemption (AC #6) ──────────────────────────────────────────────────────────────

    [Fact]
    public void SelectActiveVersion_single_certificate_activates_immediately_regardless_of_future_NotBefore()
    {
        var cert = Cert("AAA", notBefore: T0 + TimeSpan.FromDays(30));
        var timeline = BuildActivationTimeline([cert]);

        var active = SelectActiveVersion(timeline, now: T0);

        active.Should().NotBeNull();
        active!.Value.Certificate.Thumbprint.Should().Be("AAA");
    }

    [Fact]
    public void SelectActiveVersion_single_expired_certificate_fails_closed()
    {
        var cert = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(400), notAfter: T0 - TimeSpan.FromDays(1));
        var timeline = BuildActivationTimeline([cert]);

        var active = SelectActiveVersion(timeline, now: T0);

        active.Should().BeNull("the bootstrap exemption covers NotBefore timing only, not expiry");
    }

    // ── Two-certificate rotation (AC #5) ─────────────────────────────────────────────────────────

    [Fact]
    public void SelectActiveVersion_two_certificates_the_one_whose_NotBefore_has_arrived_and_is_most_recent_is_active()
    {
        var predecessor = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(30));
        var successor = Cert("BBB", notBefore: T0 - TimeSpan.FromDays(1));
        var timeline = BuildActivationTimeline([predecessor, successor]);

        var active = SelectActiveVersion(timeline, now: T0);

        active!.Value.Certificate.Thumbprint.Should().Be("BBB");
    }

    [Fact]
    public void SelectActiveVersion_flips_to_successor_once_its_NotBefore_arrives()
    {
        var predecessor = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(30));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        var successor = Cert("BBB", notBefore: successorNotBefore);
        var timeline = BuildActivationTimeline([predecessor, successor]);

        SelectActiveVersion(timeline, now: T0)!.Value.Certificate.Thumbprint.Should().Be("AAA", "successor has not activated yet");
        SelectActiveVersion(timeline, now: successorNotBefore)!.Value.Certificate.Thumbprint.Should().Be("BBB", "successor's NotBefore has now arrived");
    }

    [Fact]
    public void SelectIncludedCertificates_includes_both_when_successor_is_not_yet_active()
    {
        var predecessor = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(30));
        var successor = Cert("BBB", notBefore: T0 + TimeSpan.FromDays(1));
        var timeline = BuildActivationTimeline([predecessor, successor]);
        var active = SelectActiveVersion(timeline, now: T0)!.Value;

        var included = SelectIncludedCertificates(timeline, active, now: T0, DefaultRetirementWindow);

        included.Should().HaveCount(2, "both certificates must appear in JWKS during the overlap window (AC #4)");
        included[0].Certificate.Thumbprint.Should().Be("AAA", "the active certificate is always first");
        included.Should().Contain(e => e.Certificate.Thumbprint == "BBB");
    }

    [Fact]
    public void SelectIncludedCertificates_retirement_of_predecessor_is_measured_from_successors_ActivatesAt()
    {
        var predecessor = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(30));
        var successorNotBefore = T0 - TimeSpan.FromMinutes(30);
        var successor = Cert("BBB", notBefore: successorNotBefore);
        var timeline = BuildActivationTimeline([predecessor, successor]);
        var active = SelectActiveVersion(timeline, now: T0)!.Value;
        active.Certificate.Thumbprint.Should().Be("BBB");

        // Predecessor's retirement clock started at successor's ActivatesAt (30 min ago), not at
        // "now" and not at the predecessor's own NotBefore.
        var stillWithinWindow = SelectIncludedCertificates(timeline, active, now: T0, retirementWindow: TimeSpan.FromHours(1));
        stillWithinWindow.Should().Contain(e => e.Certificate.Thumbprint == "AAA", "30 minutes since retirement is within a 1-hour window");

        var pastWindow = SelectIncludedCertificates(timeline, active, now: T0, retirementWindow: TimeSpan.FromMinutes(10));
        pastWindow.Should().NotContain(e => e.Certificate.Thumbprint == "AAA", "30 minutes since retirement exceeds a 10-minute window");
    }

    [Fact]
    public void SelectIncludedCertificates_still_includes_predecessor_exactly_at_the_retirement_window_boundary()
    {
        var successorNotBefore = T0 - TimeSpan.FromHours(1);
        var predecessor = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(30));
        var successor = Cert("BBB", notBefore: successorNotBefore);
        var timeline = BuildActivationTimeline([predecessor, successor]);
        var active = SelectActiveVersion(timeline, now: T0)!.Value;

        var included = SelectIncludedCertificates(timeline, active, now: T0, retirementWindow: TimeSpan.FromHours(1));

        included.Should().Contain(e => e.Certificate.Thumbprint == "AAA", "exactly at the boundary is still within the window (<=)");
    }

    [Fact]
    public void A_certificate_whose_NotAfter_precedes_its_own_NotBefore_is_never_a_real_successor()
    {
        // A malformed/degenerate registration (NotAfter before NotBefore - never true of a validly
        // issued X.509 certificate, but defended against anyway): "BBB" would chronologically
        // activate before "CCC" but is already past its own NotAfter at that very instant, so it
        // can never win SelectActiveVersion's selection - it must not gate "AAA"'s retirement.
        var predecessor = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(30));
        var neverReallyActive = new RegisteredCertificateInfo(
            "BBB", NotBefore: T0 - TimeSpan.FromDays(10), NotAfter: T0 - TimeSpan.FromDays(11));
        var realSuccessor = Cert("CCC", notBefore: T0 - TimeSpan.FromDays(1));
        var timeline = BuildActivationTimeline([predecessor, neverReallyActive, realSuccessor]);

        var active = SelectActiveVersion(timeline, now: T0)!.Value;
        active.Certificate.Thumbprint.Should().Be("CCC");

        var aaaEntry = timeline.Single(e => e.Certificate.Thumbprint == "AAA");
        aaaEntry.RetiredAt.Should().Be(realSuccessor.NotBefore,
            "AAA's retirement must be anchored to CCC's ActivatesAt, not BBB's, since BBB could never have actually won the selection");
    }

    [Fact]
    public void SelectActiveVersion_returns_null_when_all_registered_certificates_are_not_yet_active()
    {
        var a = Cert("AAA", notBefore: T0 + TimeSpan.FromDays(1));
        var b = Cert("BBB", notBefore: T0 + TimeSpan.FromDays(2));
        var timeline = BuildActivationTimeline([a, b]);

        var active = SelectActiveVersion(timeline, now: T0);

        active.Should().BeNull("2+ certificates with none yet activated must fail closed, not silently pick one");
    }

    // ── HasTooSoonPendingActivation (AC #7) ──────────────────────────────────────────────────────

    [Fact]
    public void HasTooSoonPendingActivation_true_when_soonest_pending_NotBefore_is_closer_than_RefreshInterval()
    {
        var active = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(1));
        var pending = Cert("BBB", notBefore: T0 + TimeSpan.FromMinutes(1));
        var timeline = BuildActivationTimeline([active, pending]);
        var activeEntry = timeline.Single(e => e.Certificate.Thumbprint == "AAA");

        var hasWarning = HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out var soonest);

        hasWarning.Should().BeTrue();
        soonest!.Value.Certificate.Thumbprint.Should().Be("BBB");
    }

    [Fact]
    public void HasTooSoonPendingActivation_false_when_soonest_pending_NotBefore_is_RefreshInterval_or_further_away()
    {
        var active = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(1));
        var pending = Cert("BBB", notBefore: T0 + DefaultRefreshInterval);
        var timeline = BuildActivationTimeline([active, pending]);
        var activeEntry = timeline.Single(e => e.Certificate.Thumbprint == "AAA");

        var hasWarning = HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out _);

        hasWarning.Should().BeFalse("exactly RefreshInterval away is sufficient lead time, not 'too soon'");
    }

    [Fact]
    public void HasTooSoonPendingActivation_false_with_only_one_registered_certificate()
    {
        var only = Cert("AAA", notBefore: T0 + TimeSpan.FromDays(30));
        var timeline = BuildActivationTimeline([only]);
        var activeEntry = timeline.Single();

        var hasWarning = HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out var soonest);

        hasWarning.Should().BeFalse("the warning only applies once a rotation is actually in progress (2+ certificates)");
        soonest.Should().BeNull();
    }

    [Fact]
    public void HasTooSoonPendingActivation_false_when_no_certificate_is_pending()
    {
        var a = Cert("AAA", notBefore: T0 - TimeSpan.FromDays(2));
        var b = Cert("BBB", notBefore: T0 - TimeSpan.FromDays(1));
        var timeline = BuildActivationTimeline([a, b]);
        var activeEntry = timeline.Single(e => e.Certificate.Thumbprint == "BBB");

        var hasWarning = HasTooSoonPendingActivation(timeline, activeEntry, T0, DefaultRefreshInterval, out var soonest);

        hasWarning.Should().BeFalse();
        soonest.Should().BeNull();
    }
}
