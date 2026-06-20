using System.Reflection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

public sealed class AuthorizationCodeEntryTests
{
    // ── Shared fixture ────────────────────────────────────────────────────────────────────────────

    private static AuthorizationCodeEntry BuildMinimal() =>
        new()
        {
            ClientId = "client-a",
            RedirectUri = "https://app/callback",
            CodeChallenge = "abc123_challenge",
            CodeChallengeMethod = CodeChallengeMethod.S256,
            Sub = "user-42",
            Scope = "openid profile",
            SsoSessionId = "session-1",
            InteractionId = "interaction-1",
            AuthTime = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            IssuedAt = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2026, 1, 1, 12, 1, 0, TimeSpan.Zero),
        };

    // ── Type shape ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AuthorizationCodeEntry_is_in_the_ZeeKayDa_Auth_Stores_namespace()
    {
        typeof(AuthorizationCodeEntry).Namespace.Should().Be("ZeeKayDa.Auth.Stores");
    }

    [Fact]
    public void AuthorizationCodeEntry_has_exactly_14_public_instance_properties()
    {
        // Guards against an accidental addition or removal of properties that would break
        // the contract defined in ADR 0008 §2 (11 required + 3 nullable = 14 total).
        var properties = typeof(AuthorizationCodeEntry)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance);

        properties.Should().HaveCount(14,
            because: "ADR 0008 §2 defines exactly 11 required and 3 nullable properties");
    }

    [Theory]
    [InlineData(nameof(AuthorizationCodeEntry.ClientId))]
    [InlineData(nameof(AuthorizationCodeEntry.RedirectUri))]
    [InlineData(nameof(AuthorizationCodeEntry.CodeChallenge))]
    [InlineData(nameof(AuthorizationCodeEntry.CodeChallengeMethod))]
    [InlineData(nameof(AuthorizationCodeEntry.Sub))]
    [InlineData(nameof(AuthorizationCodeEntry.Scope))]
    [InlineData(nameof(AuthorizationCodeEntry.AuthTime))]
    [InlineData(nameof(AuthorizationCodeEntry.SsoSessionId))]
    [InlineData(nameof(AuthorizationCodeEntry.InteractionId))]
    [InlineData(nameof(AuthorizationCodeEntry.IssuedAt))]
    [InlineData(nameof(AuthorizationCodeEntry.ExpiresAt))]
    public void Required_property_is_decorated_with_RequiredMemberAttribute(string propertyName)
    {
        // The C# `required` keyword emits RequiredMemberAttribute on the property in IL.
        // This test guarantees that a refactor cannot silently drop `required` from a property
        // without being caught — which would weaken the object-initialiser enforcement at
        // all call sites.
        var property = typeof(AuthorizationCodeEntry)
            .GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance)!;

        property.GetCustomAttributesData()
            .Should().Contain(a => a.AttributeType.Name == "RequiredMemberAttribute",
                because: $"{propertyName} must be marked 'required' in IL (ADR 0008 §2)");
    }

    [Theory]
    [InlineData(nameof(AuthorizationCodeEntry.Nonce))]
    [InlineData(nameof(AuthorizationCodeEntry.Acr))]
    [InlineData(nameof(AuthorizationCodeEntry.Amr))]
    public void Nullable_property_is_NOT_decorated_with_RequiredMemberAttribute(string propertyName)
    {
        // The three nullable/optional properties must NOT carry RequiredMemberAttribute —
        // they are intentionally omittable for pure OAuth 2.0 flows.
        var property = typeof(AuthorizationCodeEntry)
            .GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance)!;

        property.GetCustomAttributesData()
            .Should().NotContain(a => a.AttributeType.Name == "RequiredMemberAttribute",
                because: $"{propertyName} is an optional property and must NOT be marked 'required'");
    }

    [Fact]
    public void AuthorizationCodeEntry_is_a_sealed_record()
    {
        var t = typeof(AuthorizationCodeEntry);

        t.IsSealed.Should().BeTrue();
        t.IsValueType.Should().BeFalse();

        // Records expose a compiler-synthesised Clone method
        t.GetMethod("<Clone>$").Should().NotBeNull(
            because: "the type must be a record (Clone method is generated for records)");
    }

    [Fact]
    public void AuthorizationCodeEntry_cannot_be_subclassed()
    {
        // Because the class is sealed the only way to verify this at runtime is reflection —
        // a direct inheritance attempt would be a compile error.
        typeof(AuthorizationCodeEntry).IsSealed.Should().BeTrue();
    }

    [Fact]
    public void AuthorizationCodeEntry_does_not_expose_a_raw_code_handle_property()
    {
        // Security contract: the cleartext code handle must never live on the entry.
        var properties = typeof(AuthorizationCodeEntry).GetProperties(BindingFlags.Public | BindingFlags.Instance);

        var suspiciousNames = properties
            .Select(p => p.Name)
            .Where(n => n.Contains("Code", StringComparison.OrdinalIgnoreCase)
                        && !n.Equals("CodeChallenge", StringComparison.Ordinal)
                        && !n.Equals("CodeChallengeMethod", StringComparison.Ordinal))
            .ToList();

        suspiciousNames.Should().BeEmpty(
            because: "raw code handles must never be stored on the entry — only the challenge hash");
    }

    // ── Required property storage ─────────────────────────────────────────────────────────────────

    [Fact]
    public void ClientId_is_stored_by_init()
    {
        var entry = BuildMinimal() with { ClientId = "my-client" };

        entry.ClientId.Should().Be("my-client");
    }

    [Fact]
    public void RedirectUri_is_stored_by_init()
    {
        var entry = BuildMinimal() with { RedirectUri = "https://example.com/cb" };

        entry.RedirectUri.Should().Be("https://example.com/cb");
    }

    [Fact]
    public void CodeChallenge_is_stored_by_init()
    {
        var entry = BuildMinimal() with { CodeChallenge = "challenge-value" };

        entry.CodeChallenge.Should().Be("challenge-value");
    }

    [Fact]
    public void CodeChallengeMethod_is_stored_by_init()
    {
        var entry = BuildMinimal() with { CodeChallengeMethod = CodeChallengeMethod.S256 };

        entry.CodeChallengeMethod.Should().Be(CodeChallengeMethod.S256);
    }

    [Fact]
    public void Sub_is_stored_by_init()
    {
        var entry = BuildMinimal() with { Sub = "sub-99" };

        entry.Sub.Should().Be("sub-99");
    }

    [Fact]
    public void Scope_is_stored_by_init()
    {
        var entry = BuildMinimal() with { Scope = "openid email" };

        entry.Scope.Should().Be("openid email");
    }

    [Fact]
    public void SsoSessionId_is_stored_by_init()
    {
        var entry = BuildMinimal() with { SsoSessionId = "session-xyz" };

        entry.SsoSessionId.Should().Be("session-xyz");
    }

    [Fact]
    public void InteractionId_is_stored_by_init()
    {
        var entry = BuildMinimal() with { InteractionId = "interaction-xyz" };

        entry.InteractionId.Should().Be("interaction-xyz");
    }

    [Fact]
    public void AuthTime_is_stored_by_init()
    {
        var authTime = new DateTimeOffset(2025, 6, 15, 9, 0, 0, TimeSpan.Zero);
        var entry = BuildMinimal() with { AuthTime = authTime };

        entry.AuthTime.Should().Be(authTime);
    }

    [Fact]
    public void IssuedAt_is_stored_by_init()
    {
        var issuedAt = new DateTimeOffset(2025, 6, 15, 9, 0, 0, TimeSpan.Zero);
        var entry = BuildMinimal() with { IssuedAt = issuedAt };

        entry.IssuedAt.Should().Be(issuedAt);
    }

    [Fact]
    public void ExpiresAt_is_stored_by_init()
    {
        var expiresAt = new DateTimeOffset(2025, 6, 15, 9, 1, 0, TimeSpan.Zero);
        var entry = BuildMinimal() with { ExpiresAt = expiresAt };

        entry.ExpiresAt.Should().Be(expiresAt);
    }

    // ── Nullable / optional properties default to null ────────────────────────────────────────────

    [Fact]
    public void Nonce_defaults_to_null_when_omitted()
    {
        var entry = BuildMinimal();

        entry.Nonce.Should().BeNull();
    }

    [Fact]
    public void Acr_defaults_to_null_when_omitted()
    {
        var entry = BuildMinimal();

        entry.Acr.Should().BeNull();
    }

    [Fact]
    public void Amr_defaults_to_null_when_omitted()
    {
        var entry = BuildMinimal();

        entry.Amr.Should().BeNull();
    }

    [Fact]
    public void Nonce_is_stored_when_provided()
    {
        var entry = BuildMinimal() with { Nonce = "nonce-abc" };

        entry.Nonce.Should().Be("nonce-abc");
    }

    [Fact]
    public void Acr_is_stored_when_provided()
    {
        var entry = BuildMinimal() with { Acr = "urn:mfa" };

        entry.Acr.Should().Be("urn:mfa");
    }

    [Fact]
    public void Amr_is_stored_when_provided()
    {
        var entry = BuildMinimal() with { Amr = ["pwd", "otp"] };

        entry.Amr.Should().BeEquivalentTo(["pwd", "otp"]);
    }

    // ── Record equality ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Two_entries_with_identical_values_are_equal()
    {
        var a = BuildMinimal();
        var b = BuildMinimal();

        a.Should().Be(b);
        (a == b).Should().BeTrue();
    }

    [Fact]
    public void Two_entries_differing_in_ClientId_are_not_equal()
    {
        var a = BuildMinimal() with { ClientId = "client-a" };
        var b = BuildMinimal() with { ClientId = "client-b" };

        a.Should().NotBe(b);
        (a == b).Should().BeFalse();
    }

    [Fact]
    public void Two_entries_differing_in_Sub_are_not_equal()
    {
        var a = BuildMinimal() with { Sub = "user-1" };
        var b = BuildMinimal() with { Sub = "user-2" };

        a.Should().NotBe(b);
    }

    [Fact]
    public void Two_entries_differing_in_Scope_are_not_equal()
    {
        var a = BuildMinimal() with { Scope = "openid" };
        var b = BuildMinimal() with { Scope = "openid profile" };

        a.Should().NotBe(b);
    }

    [Fact]
    public void Two_entries_differing_in_Nonce_are_not_equal()
    {
        var a = BuildMinimal() with { Nonce = null };
        var b = BuildMinimal() with { Nonce = "nonce-xyz" };

        a.Should().NotBe(b);
    }

    [Fact]
    public void Equal_entries_have_the_same_hash_code()
    {
        var a = BuildMinimal();
        var b = BuildMinimal();

        a.GetHashCode().Should().Be(b.GetHashCode());
    }

    // ── With-expression (non-destructive mutation) ────────────────────────────────────────────────

    [Fact]
    public void With_expression_produces_a_new_instance_with_changed_value()
    {
        var original = BuildMinimal();

        var modified = original with { Sub = "user-modified" };

        modified.Sub.Should().Be("user-modified");
        original.Sub.Should().Be("user-42", because: "the original must be unchanged");
    }

    [Fact]
    public void With_expression_preserves_unchanged_fields()
    {
        var original = BuildMinimal();

        var modified = original with { Sub = "user-modified" };

        modified.ClientId.Should().Be(original.ClientId);
        modified.RedirectUri.Should().Be(original.RedirectUri);
        modified.Scope.Should().Be(original.Scope);
    }
}
