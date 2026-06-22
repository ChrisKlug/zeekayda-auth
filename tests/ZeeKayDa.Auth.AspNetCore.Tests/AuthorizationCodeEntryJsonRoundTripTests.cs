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
            CodeChallenge = "abc123_challenge",
            CodeChallengeMethod = CodeChallengeMethod.S256,
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
