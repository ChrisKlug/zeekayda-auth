using System.Text.Json;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class AuthorizationCodeEntryJsonRoundTripTests
{
    private static AuthorizationCodeEntry BuildBase() =>
        new()
        {
            ClientId = "client-a",
            RedirectUri = "https://app/callback",
            Pkce = new PkceChallenge("abc123_challenge", CodeChallengeMethod.S256),
            Sub = "user-42",
            Scope = ["openid", "profile"],
            SsoSessionId = "session-1",
            InteractionId = "interaction-1",
            AuthTime = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            IssuedAt = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2026, 1, 1, 12, 1, 0, TimeSpan.Zero),
        };

    [Fact]
    public void AuthorizationCodeEntry_with_null_Amr_round_trips_through_StoreJsonSerializerContext()
    {
        var entry = BuildBase() with { Amr = null };

        var json = JsonSerializer.Serialize(entry, StoreJsonSerializerContext.Default.AuthorizationCodeEntry);
        var deserialized = JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.AuthorizationCodeEntry)!;

        deserialized.Amr.Should().BeNull();
        deserialized.ClientId.Should().Be(entry.ClientId);
        deserialized.Sub.Should().Be(entry.Sub);
        deserialized.Scope.Should().BeEquivalentTo(entry.Scope);
    }

    [Fact]
    public void AuthorizationCodeEntry_with_a_PKCE_binding_round_trips_through_StoreJsonSerializerContext()
    {
        var entry = BuildBase();

        var json = JsonSerializer.Serialize(entry, StoreJsonSerializerContext.Default.AuthorizationCodeEntry);
        var deserialized = JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.AuthorizationCodeEntry)!;

        deserialized.Pkce.Should().Be(new PkceChallenge("abc123_challenge", CodeChallengeMethod.S256));
    }

    [Fact]
    public void AuthorizationCodeEntry_without_a_PKCE_binding_round_trips_through_StoreJsonSerializerContext()
    {
        var entry = BuildBase() with { Pkce = null };

        var json = JsonSerializer.Serialize(entry, StoreJsonSerializerContext.Default.AuthorizationCodeEntry);
        var deserialized = JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.AuthorizationCodeEntry)!;

        deserialized.Pkce.Should().BeNull();
    }

    [Theory]
    [InlineData("""{"challenge":"","method":"S256"}""")]
    [InlineData("""{"challenge":"abc123_challenge","method":"plain"}""")]
    public void AuthorizationCodeEntry_with_an_incomplete_PKCE_binding_does_not_deserialize(string pkce)
    {
        var json = JsonSerializer.Serialize(BuildBase(), StoreJsonSerializerContext.Default.AuthorizationCodeEntry)
            .Replace("""{"challenge":"abc123_challenge","method":"S256"}""", pkce, StringComparison.Ordinal);
        json.Should().Contain(pkce, "the substitution must have hit the binding");

        var act = () => JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.AuthorizationCodeEntry);

        act.Should().Throw<Exception>("a binding a store hands back is complete or it is not a binding")
            .Which.Should().Match(e => e is JsonException || e is ArgumentException);
    }

    [Fact]
    public void AuthorizationCodeEntry_with_empty_Amr_round_trips_through_StoreJsonSerializerContext()
    {
        var entry = BuildBase() with { Amr = [] };

        var json = JsonSerializer.Serialize(entry, StoreJsonSerializerContext.Default.AuthorizationCodeEntry);
        var deserialized = JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.AuthorizationCodeEntry)!;

        deserialized.Amr.Should().NotBeNull().And.BeEmpty();
    }

    [Fact]
    public void AuthorizationCodeEntry_with_non_empty_Amr_round_trips_through_StoreJsonSerializerContext()
    {
        var entry = BuildBase() with { Amr = ["pwd", "mfa"] };

        var json = JsonSerializer.Serialize(entry, StoreJsonSerializerContext.Default.AuthorizationCodeEntry);
        var deserialized = JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.AuthorizationCodeEntry)!;

        deserialized.Amr.Should().BeEquivalentTo(["pwd", "mfa"]);
    }
}
