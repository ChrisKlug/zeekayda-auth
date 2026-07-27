using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class KeySourceOptionsTests
{
    private sealed class FakeKeySourceOptions : KeySourceOptions
    {
    }

    [Fact]
    public void PublicationLead_defaults_to_RefreshInterval_when_unset()
    {
        var options = new FakeKeySourceOptions { RefreshInterval = TimeSpan.FromMinutes(42) };

        options.PublicationLead.Should().Be(TimeSpan.FromMinutes(42));
    }

    [Fact]
    public void PublicationLead_tracks_a_later_RefreshInterval_change_while_still_unset()
    {
        // Because "unset" resolves dynamically from RefreshInterval rather than being snapshotted
        // at first read, changing RefreshInterval before PublicationLead is ever explicitly set
        // must be reflected.
        var options = new FakeKeySourceOptions { RefreshInterval = TimeSpan.FromMinutes(5) };
        options.RefreshInterval = TimeSpan.FromMinutes(15);

        options.PublicationLead.Should().Be(TimeSpan.FromMinutes(15));
    }

    [Fact]
    public void PublicationLead_returns_the_explicitly_set_value_once_set()
    {
        var options = new FakeKeySourceOptions
        {
            RefreshInterval = TimeSpan.FromMinutes(5),
            PublicationLead = TimeSpan.FromHours(2),
        };

        options.PublicationLead.Should().Be(TimeSpan.FromHours(2));
    }

    [Fact]
    public void RefreshInterval_defaults_to_one_hour()
    {
        var options = new FakeKeySourceOptions();

        options.RefreshInterval.Should().Be(TimeSpan.FromHours(1));
    }

    // ── Defensive PublicationLead >= RefreshInterval assertion (issue #425 security review, finding F6) ──

    [Fact]
    public void PublicationLead_throws_ZeeKayDaConfigurationException_when_explicitly_set_shorter_than_RefreshInterval()
    {
        // The primary enforcement of this invariant is KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval,
        // run by each provider's IValidateOptions at options-bind time — but that never runs for an
        // options instance built directly like this, bypassing the DI options pipeline entirely.
        // This is exactly the gap the getter-level assertion exists to close.
        var options = new FakeKeySourceOptions
        {
            RefreshInterval = TimeSpan.FromMinutes(30),
            PublicationLead = TimeSpan.FromMinutes(10),
        };

        var act = () => options.PublicationLead;

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*PublicationLead*must be greater than or equal to*RefreshInterval*");
    }

    [Fact]
    public void PublicationLead_does_not_throw_when_explicitly_set_equal_to_RefreshInterval()
    {
        var options = new FakeKeySourceOptions
        {
            RefreshInterval = TimeSpan.FromMinutes(30),
            PublicationLead = TimeSpan.FromMinutes(30),
        };

        var act = () => options.PublicationLead;

        act.Should().NotThrow();
    }

    [Fact]
    public void PublicationLead_does_not_throw_for_the_derived_default_even_when_RefreshInterval_is_very_short()
    {
        // The derived default (falling back to RefreshInterval itself) can never violate the
        // invariant by construction — only an explicitly set PublicationLead can.
        var options = new FakeKeySourceOptions { RefreshInterval = TimeSpan.FromSeconds(1) };

        var act = () => options.PublicationLead;

        act.Should().NotThrow();
    }
}
