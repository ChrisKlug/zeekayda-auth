using System.Reflection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

public sealed class AuthorizationCodeEntryTests
{
    // ── Type shape ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AuthorizationCodeEntry_has_exactly_14_public_instance_properties()
    {
        // Guards against an accidental addition or removal of properties that would break
        // the contract of exactly 11 required + 3 nullable = 14 total properties.
        var properties = typeof(AuthorizationCodeEntry)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance);

        properties.Should().HaveCount(14,
            because: "the contract defines exactly 11 required and 3 nullable properties");
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
                because: $"{propertyName} must be marked 'required' in IL");
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
}
