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
}
