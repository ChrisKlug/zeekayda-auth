using System.Text.Json;
using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Tests.Claims;

/// <summary>
/// A claim value is the JSON a token will carry, built once by a conversion that never throws.
/// Serialising a value through System.Text.Json is how a custom issuer sees it, so that is how
/// these tests read it back.
/// </summary>
public sealed class ClaimValueTests
{
    private static string Json(ClaimValue value) => JsonSerializer.Serialize(value);

    [Fact]
    public void A_string_becomes_a_JSON_string()
    {
        ClaimValue value = "Chris";

        Json(value).Should().Be("\"Chris\"");
    }

    [Fact]
    public void A_boolean_becomes_a_JSON_boolean_not_a_string()
    {
        ClaimValue value = true;

        Json(value).Should().Be("true");
    }

    [Theory]
    [InlineData(42, "42")]
    [InlineData(-7, "-7")]
    public void An_int_becomes_a_JSON_number(int input, string expected)
    {
        ClaimValue value = input;

        Json(value).Should().Be(expected);
    }

    [Fact]
    public void A_long_becomes_a_JSON_number()
    {
        ClaimValue value = 1_757_764_800L;

        Json(value).Should().Be("1757764800");
    }

    [Fact]
    public void A_double_becomes_a_JSON_number()
    {
        ClaimValue value = 1.5;

        Json(value).Should().Be("1.5");
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void A_double_with_no_JSON_form_converts_without_throwing_to_a_value_no_record_accepts(double input)
    {
        ClaimValue value = input;

        value.IsRepresentable.Should().BeFalse();
    }

    [Fact]
    public void A_null_string_converts_without_throwing_to_a_value_no_record_accepts()
    {
        ClaimValue value = (string)null!;

        value.IsRepresentable.Should().BeFalse();
    }

    [Fact]
    public void An_empty_string_is_a_value_no_record_accepts()
    {
        ClaimValue value = string.Empty;

        value.IsRepresentable.Should().BeFalse("OpenID Connect Core §5.3.2 says an absent claim is omitted, never empty");
    }

    [Fact]
    public void The_default_value_is_a_value_no_record_accepts()
    {
        default(ClaimValue).IsRepresentable.Should().BeFalse();
    }

    [Fact]
    public void An_address_is_written_with_the_standard_member_names_and_null_members_omitted()
    {
        ClaimValue value = new AddressClaim
        {
            Formatted = "1 Main St\nTown",
            StreetAddress = "1 Main St",
            PostalCode = "12345",
            Country = "SE",
        };

        Json(value).Should().Be("{\"formatted\":\"1 Main St\\nTown\",\"street_address\":\"1 Main St\",\"postal_code\":\"12345\",\"country\":\"SE\"}");
    }

    [Fact]
    public void A_null_address_converts_without_throwing_to_a_value_no_record_accepts()
    {
        ClaimValue value = (AddressClaim)null!;

        value.IsRepresentable.Should().BeFalse();
    }

    [Fact]
    public void From_serialises_a_custom_object_with_snake_case_names_by_default()
    {
        var value = ClaimValue.From(new TenantInfo("acme", "eu-north"));

        Json(value).Should().Be("{\"tenant_id\":\"acme\",\"home_region\":\"eu-north\"}");
    }

    [Fact]
    public void From_honours_the_options_it_is_given()
    {
        var value = ClaimValue.From(new TenantInfo("acme", "eu-north"), new JsonSerializerOptions(JsonSerializerDefaults.General));

        Json(value).Should().Be("{\"TenantId\":\"acme\",\"HomeRegion\":\"eu-north\"}");
    }

    [Fact]
    public void From_serialises_an_array_as_one_value()
    {
        var value = ClaimValue.From(new[] { "admin", "editor" });

        Json(value).Should().Be("[\"admin\",\"editor\"]");
        value.Kind.Should().Be(JsonValueKind.Array);
    }

    [Fact]
    public void From_detaches_the_JSON_from_the_object_it_was_built_from()
    {
        var roles = new List<string> { "admin" };
        var value = ClaimValue.From(roles);

        roles.Add("editor");

        Json(value).Should().Be("[\"admin\"]", "a token is built from what the provider handed over, not from what it mutated afterwards");
    }

    [Fact]
    public void From_of_a_JSON_null_is_a_value_no_record_accepts()
    {
        var value = ClaimValue.From<object>(null!);

        value.IsRepresentable.Should().BeFalse();
    }

    [Fact]
    public void Two_values_built_from_equal_input_are_equal()
    {
        ClaimValue first = "Chris";
        ClaimValue second = "Chris";

        first.Should().Be(second);
    }

    [Fact]
    public void ToString_names_the_kind_and_never_the_value()
    {
        ClaimValue value = "chris@example.com";

        value.ToString().Should().Be("ClaimValue(String)");
    }

    [Fact]
    public void A_custom_issuer_reads_the_kind_and_writes_the_JSON_without_a_serializer_round_trip()
    {
        ClaimValue value = new AddressClaim { Country = "SE" };
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("address");
            value.WriteTo(writer);
            writer.WriteEndObject();
        }

        value.Kind.Should().Be(JsonValueKind.Object);
        System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan).Should().Be("{\"address\":{\"country\":\"SE\"}}");
    }

    [Fact]
    public void The_default_value_cannot_be_written_to_a_writer()
    {
        using var writer = new Utf8JsonWriter(new System.Buffers.ArrayBufferWriter<byte>());

        var act = () => default(ClaimValue).WriteTo(writer);

        act.Should().Throw<InvalidOperationException>();
        default(ClaimValue).Kind.Should().Be(JsonValueKind.Undefined);
    }

    [Fact]
    public void The_default_value_cannot_be_serialised()
    {
        var act = () => JsonSerializer.Serialize(default(ClaimValue));

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void A_value_round_trips_through_deserialisation_as_the_same_JSON()
    {
        var value = JsonSerializer.Deserialize<ClaimValue>("{\"a\":[1,2]}");

        Json(value).Should().Be("{\"a\":[1,2]}");
        value.Kind.Should().Be(JsonValueKind.Object);
    }

    private sealed record TenantInfo(string TenantId, string HomeRegion);
}
