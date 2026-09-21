using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using ZeeKayDa.Auth.AspNetCore.Providers;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// The recorder is how <c>HandlerOptionsStartupActivator</c> knows which of an options resolution's
/// validation failures the framework itself produced. Recovering that from the failure strings is
/// what this type exists to replace, so its identity and lifetime rules are the guarantee: a
/// reading that is not scoped to the attempt it describes would let the activator name a member the
/// operator never configured, or attribute one options type's pin assertions to another.
/// </summary>
public sealed class PinnedOptionDriftRecorderTests
{
    private static readonly PinnedOptionDrift Drift = new("SignInScheme", "zkd.external");

    [Fact]
    public void A_record_is_not_visible_under_a_different_options_type()
    {
        // The validator is registered open-generic, so it runs for every options type resolved
        // under a name the provider registry knows. Keyed by name alone, a nested resolution of a
        // second options type would overwrite the outer one's findings.
        var sut = new PinnedOptionDriftRecorder();

        sut.Record("acme", typeof(OAuthOptions), [Drift]);

        sut.DriftsFor("acme", typeof(OAuthOptions)).Should().ContainSingle();
        sut.DriftsFor("acme", typeof(AuthenticationSchemeOptions)).Should().BeEmpty();
    }

    [Fact]
    public void A_record_is_not_visible_under_a_different_provider_name()
    {
        var sut = new PinnedOptionDriftRecorder();

        sut.Record("acme", typeof(OAuthOptions), [Drift]);

        sut.DriftsFor("other", typeof(OAuthOptions)).Should().BeEmpty();
    }

    [Fact]
    public void Clearing_discards_an_earlier_attempts_findings()
    {
        // What makes the activator's read attempt-scoped: it clears before resolving, so a
        // resolution that throws before the framework's validator runs reports no pin assertions
        // rather than whichever attempt recorded last.
        var sut = new PinnedOptionDriftRecorder();
        sut.Record("acme", typeof(OAuthOptions), [Drift]);

        sut.Clear("acme", typeof(OAuthOptions));

        sut.DriftsFor("acme", typeof(OAuthOptions)).Should().BeEmpty();
    }

    [Fact]
    public void Clearing_one_key_leaves_another_untouched()
    {
        var sut = new PinnedOptionDriftRecorder();
        sut.Record("acme", typeof(OAuthOptions), [Drift]);
        sut.Record("other", typeof(OAuthOptions), [Drift]);

        sut.Clear("acme", typeof(OAuthOptions));

        sut.DriftsFor("other", typeof(OAuthOptions)).Should().ContainSingle();
    }

    [Fact]
    public void A_passing_run_replaces_an_earlier_failures_findings_rather_than_leaving_them()
    {
        // Validation runs again on every resolve once it has failed, so a drift the operator has
        // since fixed must not survive as a stale finding.
        var sut = new PinnedOptionDriftRecorder();
        sut.Record("acme", typeof(OAuthOptions), [Drift]);

        sut.Record("acme", typeof(OAuthOptions), []);

        sut.DriftsFor("acme", typeof(OAuthOptions)).Should().BeEmpty();
    }

    [Fact]
    public void An_unrecorded_key_reads_as_no_findings()
    {
        var sut = new PinnedOptionDriftRecorder();

        sut.DriftsFor("never-recorded", typeof(OAuthOptions)).Should().BeEmpty();
    }
}
