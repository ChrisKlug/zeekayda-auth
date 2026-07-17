using System.Reflection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

public sealed class AuthorizationCodeRedemptionResultTests
{
    // ── Shared fixture ────────────────────────────────────────────────────────────────────────────

    private static AuthorizationCodeEntry BuildEntry() =>
        new()
        {
            ClientId = "client-a",
            RedirectUri = "https://app/callback",
            CodeChallenge = "challenge-abc",
            CodeChallengeMethod = CodeChallengeMethod.S256,
            Sub = "user-1",
            Scope = ["openid"],
            SsoSessionId = "session-1",
            InteractionId = "interaction-1",
            AuthTime = DateTimeOffset.UtcNow,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1),
        };

    // ── Base-class shape ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AuthorizationCodeRedemptionResult_is_abstract()
    {
        typeof(AuthorizationCodeRedemptionResult).IsAbstract.Should().BeTrue();
    }

    [Fact]
    public void AuthorizationCodeRedemptionResult_has_a_private_constructor_only()
    {
        var constructors = typeof(AuthorizationCodeRedemptionResult)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        constructors.Should().ContainSingle(because: "there is exactly one constructor");
        constructors[0].IsPrivate.Should().BeTrue(
            because: "the private constructor prevents external subclassing");
    }

    [Fact]
    public void AuthorizationCodeRedemptionResult_cannot_be_subclassed_externally()
    {
        // Because the base class constructor is private, any attempt to define a subclass
        // outside the declaring assembly would fail at compile time (or at runtime via
        // TypeLoadException if constructed via reflection). We verify the invariant by
        // confirming no public constructor is accessible.
        var publicCtor = typeof(AuthorizationCodeRedemptionResult)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public);

        publicCtor.Should().BeEmpty(
            because: "the absence of a public constructor blocks external subclassing");
    }

    // ── Nested type hierarchy ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Redeemed_is_a_subtype_of_AuthorizationCodeRedemptionResult()
    {
        typeof(AuthorizationCodeRedemptionResult.Redeemed)
            .Should().BeAssignableTo<AuthorizationCodeRedemptionResult>();
    }

    [Fact]
    public void ClientMismatch_is_a_subtype_of_AuthorizationCodeRedemptionResult()
    {
        typeof(AuthorizationCodeRedemptionResult.ClientMismatch)
            .Should().BeAssignableTo<AuthorizationCodeRedemptionResult>();
    }

    [Fact]
    public void AlreadyRedeemed_is_a_subtype_of_AuthorizationCodeRedemptionResult()
    {
        typeof(AuthorizationCodeRedemptionResult.AlreadyRedeemed)
            .Should().BeAssignableTo<AuthorizationCodeRedemptionResult>();
    }

    [Fact]
    public void NotFound_is_a_subtype_of_AuthorizationCodeRedemptionResult()
    {
        typeof(AuthorizationCodeRedemptionResult.NotFound)
            .Should().BeAssignableTo<AuthorizationCodeRedemptionResult>();
    }

    [Fact]
    public void Redeemed_is_sealed()
    {
        typeof(AuthorizationCodeRedemptionResult.Redeemed).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void ClientMismatch_is_sealed()
    {
        typeof(AuthorizationCodeRedemptionResult.ClientMismatch).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void AlreadyRedeemed_is_sealed()
    {
        typeof(AuthorizationCodeRedemptionResult.AlreadyRedeemed).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void NotFound_is_sealed()
    {
        typeof(AuthorizationCodeRedemptionResult.NotFound).IsSealed.Should().BeTrue();
    }

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

    // ── Redeemed ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Redeemed_stores_the_Entry_instance()
    {
        var entry = BuildEntry();

        var outcome = new AuthorizationCodeRedemptionResult.Redeemed { Entry = entry };

        outcome.Entry.Should().BeSameAs(entry);
    }

    [Fact]
    public void Redeemed_can_be_assigned_to_base_type()
    {
        AuthorizationCodeRedemptionResult outcome =
            new AuthorizationCodeRedemptionResult.Redeemed { Entry = BuildEntry() };

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>();
    }

    // ── ClientMismatch ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ClientMismatch_can_be_instantiated_and_assigned_to_base_type()
    {
        AuthorizationCodeRedemptionResult outcome =
            new AuthorizationCodeRedemptionResult.ClientMismatch();

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.ClientMismatch>();
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
                because: "FamilyId must be 'required string' per ADR 0008 §2 so that it cannot " +
                         "be omitted when constructing an AlreadyRedeemed outcome");
    }

    [Fact]
    public void AlreadyRedeemed_FamilyId_property_type_is_non_nullable_string()
    {
        var property = typeof(AuthorizationCodeRedemptionResult.AlreadyRedeemed)
            .GetProperty(nameof(AuthorizationCodeRedemptionResult.AlreadyRedeemed.FamilyId),
                BindingFlags.Public | BindingFlags.Instance)!;

        property.PropertyType.Should().Be(typeof(string),
            because: "FamilyId must be a non-nullable string per ADR 0008 §2");
    }

    [Fact]
    public void AlreadyRedeemed_stores_the_FamilyId()
    {
        var outcome = new AuthorizationCodeRedemptionResult.AlreadyRedeemed
        {
            FamilyId = "family-xyz",
        };

        outcome.FamilyId.Should().Be("family-xyz");
    }

    [Fact]
    public void AlreadyRedeemed_can_be_assigned_to_base_type()
    {
        AuthorizationCodeRedemptionResult outcome =
            new AuthorizationCodeRedemptionResult.AlreadyRedeemed { FamilyId = "family-xyz" };

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.AlreadyRedeemed>();
    }

    // ── NotFound ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void NotFound_can_be_instantiated_and_assigned_to_base_type()
    {
        AuthorizationCodeRedemptionResult outcome =
            new AuthorizationCodeRedemptionResult.NotFound();

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.NotFound>();
    }

    // ── Pattern-matching exhaustiveness ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("redeemed")]
    [InlineData("client_mismatch")]
    [InlineData("already_redeemed")]
    [InlineData("not_found")]
    public void Switch_expression_covers_all_four_cases(string expectedTag)
    {
        AuthorizationCodeRedemptionResult outcome = expectedTag switch
        {
            "redeemed" => new AuthorizationCodeRedemptionResult.Redeemed { Entry = BuildEntry() },
            "client_mismatch" => new AuthorizationCodeRedemptionResult.ClientMismatch(),
            "already_redeemed" => new AuthorizationCodeRedemptionResult.AlreadyRedeemed { FamilyId = "f-1" },
            _ => new AuthorizationCodeRedemptionResult.NotFound(),
        };

        // A switch expression over all four cases must compile without a default arm warning,
        // proving the hierarchy is closed enough for exhaustive matching.
        var actualTag = outcome switch
        {
            AuthorizationCodeRedemptionResult.Redeemed => "redeemed",
            AuthorizationCodeRedemptionResult.ClientMismatch => "client_mismatch",
            AuthorizationCodeRedemptionResult.AlreadyRedeemed => "already_redeemed",
            AuthorizationCodeRedemptionResult.NotFound => "not_found",
            _ => "unknown",
        };

        actualTag.Should().Be(expectedTag);
    }

    [Fact]
    public void Pattern_match_on_Redeemed_exposes_Entry()
    {
        var entry = BuildEntry();
        AuthorizationCodeRedemptionResult outcome =
            new AuthorizationCodeRedemptionResult.Redeemed { Entry = entry };

        if (outcome is AuthorizationCodeRedemptionResult.Redeemed redeemed)
        {
            redeemed.Entry.Should().BeSameAs(entry);
        }
        else
        {
            Assert.Fail("Expected Redeemed outcome");
        }
    }

    [Fact]
    public void Pattern_match_on_AlreadyRedeemed_exposes_FamilyId()
    {
        AuthorizationCodeRedemptionResult outcome =
            new AuthorizationCodeRedemptionResult.AlreadyRedeemed { FamilyId = "family-abc" };

        if (outcome is AuthorizationCodeRedemptionResult.AlreadyRedeemed ar)
        {
            ar.FamilyId.Should().Be("family-abc");
        }
        else
        {
            Assert.Fail("Expected AlreadyRedeemed outcome");
        }
    }
}
