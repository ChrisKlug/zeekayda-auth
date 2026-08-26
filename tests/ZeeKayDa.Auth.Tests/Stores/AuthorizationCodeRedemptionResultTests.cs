using System.Reflection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

public sealed class AuthorizationCodeRedemptionResultTests
{
    // ── Base-class shape ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AuthorizationCodeRedemptionResult_has_a_private_constructor_only()
    {
        var constructors = typeof(AuthorizationCodeRedemptionResult)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        constructors.Should().ContainSingle(because: "there is exactly one constructor");
        constructors[0].IsPrivate.Should().BeTrue(
            because: "the private constructor prevents external subclassing");
    }

    // ── Nested type hierarchy ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void There_are_exactly_four_concrete_subtypes()
    {
        // Guards against a future subtype being added without updating all switch sites.
        var subtypes = typeof(AuthorizationCodeRedemptionResult).Assembly
            .GetTypes()
            .Where(t => t != typeof(AuthorizationCodeRedemptionResult)
                        && typeof(AuthorizationCodeRedemptionResult).IsAssignableFrom(t))
            .ToList();

        subtypes.Should().HaveCount(4, because: "the closed union has exactly four cases");
    }

    // ── AlreadyRedeemed ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AlreadyRedeemed_FamilyId_is_decorated_with_RequiredMemberAttribute()
    {
        // AC-6: FamilyId must be `required string` (non-nullable). The compiler emits
        // RequiredMemberAttribute on the property when `required` is present in source.
        // This test ensures a refactor cannot silently drop the `required` keyword.
        var property = typeof(AuthorizationCodeRedemptionResult.AlreadyRedeemed)
            .GetProperty(nameof(AuthorizationCodeRedemptionResult.AlreadyRedeemed.FamilyId),
                BindingFlags.Public | BindingFlags.Instance)!;

        property.GetCustomAttributesData()
            .Should().Contain(a => a.AttributeType.Name == "RequiredMemberAttribute",
                because: "FamilyId must be 'required string' so that it cannot " +
                         "be omitted when constructing an AlreadyRedeemed outcome");
    }

    [Fact]
    public void AlreadyRedeemed_FamilyId_property_type_is_non_nullable_string()
    {
        var property = typeof(AuthorizationCodeRedemptionResult.AlreadyRedeemed)
            .GetProperty(nameof(AuthorizationCodeRedemptionResult.AlreadyRedeemed.FamilyId),
                BindingFlags.Public | BindingFlags.Instance)!;

        property.PropertyType.Should().Be(typeof(string),
            because: "FamilyId must be a non-nullable string");
    }
}
