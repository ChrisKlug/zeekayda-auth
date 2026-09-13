using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Tests.Claims;

/// <summary>
/// The record's constructor is the one place a claim is validated, and its message names the
/// claim type and never the value.
/// </summary>
public sealed class ClaimRecordTests
{
    [Fact]
    public void A_record_carries_its_type_and_value()
    {
        var record = new ClaimRecord("email_verified", true);

        record.Type.Should().Be("email_verified");
        record.Value.Should().Be((ClaimValue)true);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_blank_type_is_refused(string? type)
    {
        var act = () => new ClaimRecord(type!, "value");

        act.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("type");
    }

    [Fact]
    public void A_null_string_value_is_refused_by_claim_type()
    {
        var act = () => new ClaimRecord("email", (string)null!);

        act.Should().Throw<ArgumentException>()
            .Which.Message.Should().Contain("'email'").And.NotContain("null string");
    }

    [Fact]
    public void An_empty_string_value_is_refused()
    {
        var act = () => new ClaimRecord("email", string.Empty);

        act.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("value");
    }

    [Fact]
    public void A_NaN_value_is_refused()
    {
        var act = () => new ClaimRecord("score", double.NaN);

        act.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("value");
    }

    [Fact]
    public void A_JSON_null_from_From_is_refused()
    {
        var act = () => new ClaimRecord("tenant", ClaimValue.From<object>(null!));

        act.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("value");
    }

    [Fact]
    public void A_default_value_is_refused()
    {
        var act = () => new ClaimRecord("tenant", default);

        act.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("value");
    }

    [Fact]
    public void The_refusal_message_never_contains_the_value()
    {
        // The empty string is the one refused value with observable text; the others have none.
        var act = () => new ClaimRecord("secret", "");

        act.Should().Throw<ArgumentException>().Which.Message.Should().NotContain("\"\"");
    }

    [Fact]
    public void The_default_record_throws_from_its_members()
    {
        var record = default(ClaimRecord);

        var type = () => record.Type;
        var value = () => record.Value;

        type.Should().Throw<InvalidOperationException>();
        value.Should().Throw<InvalidOperationException>();
        record.IsDefault.Should().BeTrue();
    }

    [Fact]
    public void ToString_names_the_type_and_the_kind_and_never_the_value()
    {
        var record = new ClaimRecord("email", "chris@example.com");

        record.ToString().Should().Be("ClaimRecord(email: ClaimValue(String))");
        default(ClaimRecord).ToString().Should().Be("ClaimRecord(default)");
    }
}
