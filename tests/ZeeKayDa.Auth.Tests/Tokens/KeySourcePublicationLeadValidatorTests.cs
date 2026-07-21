using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class KeySourcePublicationLeadValidatorTests
{
    private sealed class FakeKeySourceOptions : KeySourceOptions
    {
    }

    [Fact]
    public void ValidateAtLeastRefreshInterval_returns_null_when_PublicationLead_equals_RefreshInterval()
    {
        var options = new FakeKeySourceOptions { RefreshInterval = TimeSpan.FromMinutes(5) };

        var error = KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval(nameof(FakeKeySourceOptions), options);

        error.Should().BeNull();
    }

    [Fact]
    public void ValidateAtLeastRefreshInterval_returns_null_when_PublicationLead_exceeds_RefreshInterval()
    {
        var options = new FakeKeySourceOptions
        {
            RefreshInterval = TimeSpan.FromMinutes(5),
            PublicationLead = TimeSpan.FromMinutes(10),
        };

        var error = KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval(nameof(FakeKeySourceOptions), options);

        error.Should().BeNull();
    }

    [Fact]
    public void ValidateAtLeastRefreshInterval_returns_error_when_PublicationLead_is_shorter_than_RefreshInterval()
    {
        var options = new FakeKeySourceOptions
        {
            RefreshInterval = TimeSpan.FromMinutes(10),
            PublicationLead = TimeSpan.FromMinutes(5),
        };

        var error = KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval(nameof(FakeKeySourceOptions), options);

        error.Should().NotBeNull().And.Contain("PublicationLead").And.Contain("RefreshInterval");
    }

    [Fact]
    public void ValidateAtLeastRefreshInterval_throws_when_options_is_null()
    {
        var act = () => KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval("x", null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── ValidateMinimum ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ValidateMinimum_returns_null_when_PublicationLead_equals_one_minute()
    {
        var error = KeySourcePublicationLeadValidator.ValidateMinimum("x", TimeSpan.FromMinutes(1));

        error.Should().BeNull();
    }

    [Fact]
    public void ValidateMinimum_returns_null_when_PublicationLead_exceeds_one_minute()
    {
        var error = KeySourcePublicationLeadValidator.ValidateMinimum("x", TimeSpan.FromMinutes(5));

        error.Should().BeNull();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(30)]
    public void ValidateMinimum_returns_error_when_PublicationLead_is_shorter_than_one_minute(int seconds)
    {
        var error = KeySourcePublicationLeadValidator.ValidateMinimum("x", TimeSpan.FromSeconds(seconds));

        error.Should().NotBeNull().And.Contain("PublicationLead");
    }

    [Fact]
    public void ValidateMinimum_throws_when_optionsTypeName_is_null()
    {
        var act = () => KeySourcePublicationLeadValidator.ValidateMinimum(null!, TimeSpan.FromMinutes(1));

        act.Should().Throw<ArgumentNullException>();
    }
}
