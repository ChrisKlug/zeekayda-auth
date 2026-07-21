using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class KeySourcePublicationLeadValidatorTests
{
    private sealed class FakeKeySourceOptions : KeySourceOptions
    {
    }

    [Fact]
    public void ValidateInvariant_returns_null_when_PublicationLead_equals_RefreshInterval()
    {
        var options = new FakeKeySourceOptions { RefreshInterval = TimeSpan.FromMinutes(5) };

        var error = KeySourcePublicationLeadValidator.ValidateInvariant(nameof(FakeKeySourceOptions), options);

        error.Should().BeNull();
    }

    [Fact]
    public void ValidateInvariant_returns_null_when_PublicationLead_exceeds_RefreshInterval()
    {
        var options = new FakeKeySourceOptions
        {
            RefreshInterval = TimeSpan.FromMinutes(5),
            PublicationLead = TimeSpan.FromMinutes(10),
        };

        var error = KeySourcePublicationLeadValidator.ValidateInvariant(nameof(FakeKeySourceOptions), options);

        error.Should().BeNull();
    }

    [Fact]
    public void ValidateInvariant_returns_error_when_PublicationLead_is_shorter_than_RefreshInterval()
    {
        var options = new FakeKeySourceOptions
        {
            RefreshInterval = TimeSpan.FromMinutes(10),
            PublicationLead = TimeSpan.FromMinutes(5),
        };

        var error = KeySourcePublicationLeadValidator.ValidateInvariant(nameof(FakeKeySourceOptions), options);

        error.Should().NotBeNull().And.Contain("PublicationLead").And.Contain("RefreshInterval");
    }

    [Fact]
    public void ValidateInvariant_throws_when_options_is_null()
    {
        var act = () => KeySourcePublicationLeadValidator.ValidateInvariant("x", null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
