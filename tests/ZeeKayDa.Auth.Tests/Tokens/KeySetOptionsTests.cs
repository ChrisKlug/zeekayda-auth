using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class KeySetOptionsTests
{
    private sealed class FakeKeySetOptions : KeySetOptions
    {
    }

    [Fact]
    public void PublicationLead_defaults_to_one_hour()
    {
        var options = new FakeKeySetOptions();

        options.PublicationLead.Should().Be(TimeSpan.FromHours(1));
    }

    [Fact]
    public void PublicationLead_can_be_overridden()
    {
        var options = new FakeKeySetOptions { PublicationLead = TimeSpan.FromMinutes(30) };

        options.PublicationLead.Should().Be(TimeSpan.FromMinutes(30));
    }
}
