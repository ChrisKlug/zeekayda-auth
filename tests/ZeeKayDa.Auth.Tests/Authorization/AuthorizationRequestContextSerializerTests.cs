using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Tests.Authorization;

/// <summary>
/// The interaction context's wire format (#84). It is positional and versioned, so anything it
/// does not recognise must be refused rather than misread — a positional format has no way to
/// detect a field that moved.
/// </summary>
public class AuthorizationRequestContextSerializerTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 28, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Newly_written_context_round_trips_every_field()
    {
        var context = MinimalContext();

        AuthorizationRequestContextSerializer.TryDecode(
            AuthorizationRequestContextSerializer.Encode(context), out var decoded).Should().BeTrue();

        decoded.Should().BeEquivalentTo(context);
    }

    [Fact]
    public void Fully_accumulated_context_round_trips_every_field()
    {
        // Everything #85 and #86 will add, so the format is proven against the shape it ends the
        // flow in, not only the shape it starts in.
        var context = MinimalContext() with
        {
            State = "opaque-client-state",
            MaxAge = TimeSpan.FromMinutes(15),
            Prompts = new HashSet<PromptValue> { PromptValue.Login, PromptValue.Consent },
            Scopes = ["openid", "profile", "email"],
            SsoSessionId = "session-id",
            Subject = "subject-id",
            AuthTime = Now.AddMinutes(-2),
            ProviderScheme = "facebook",
            Acr = "urn:mace:incommon:iap:silver",
            Amr = ["pwd", "mfa"],
            GrantedScopes = ["openid", "profile"],
            ConsentedAt = Now.AddMinutes(-1),
        };

        AuthorizationRequestContextSerializer.TryDecode(
            AuthorizationRequestContextSerializer.Encode(context), out var decoded).Should().BeTrue();

        decoded.Should().BeEquivalentTo(context);
    }

    [Fact]
    public void Null_and_empty_collections_stay_distinguishable()
    {
        // "no consent decision yet" and "consented to nothing" are different states, and a
        // format that flattens them would make a denial look like an unanswered prompt.
        var context = MinimalContext() with { GrantedScopes = [] };

        AuthorizationRequestContextSerializer.TryDecode(
            AuthorizationRequestContextSerializer.Encode(context), out var decoded).Should().BeTrue();

        decoded!.GrantedScopes.Should().NotBeNull().And.BeEmpty();
        MinimalContext().GrantedScopes.Should().BeNull();
    }

    [Fact]
    public void Payload_written_by_another_version_is_refused()
    {
        var payload = AuthorizationRequestContextSerializer.Encode(MinimalContext());
        payload[0] = 99;

        AuthorizationRequestContextSerializer.TryDecode(payload, out var decoded).Should().BeFalse(
            "a positional format cannot detect a moved field, so an unknown version must be " +
            "refused rather than read as if the layout still matched");
        decoded.Should().BeNull();
    }

    [Fact]
    public void Truncated_payload_is_refused_and_does_not_throw()
    {
        var payload = AuthorizationRequestContextSerializer.Encode(MinimalContext());

        AuthorizationRequestContextSerializer.TryDecode(payload.AsSpan(0, payload.Length / 2), out var decoded)
            .Should().BeFalse();
        decoded.Should().BeNull();
    }

    [Fact]
    public void Trailing_bytes_are_refused()
    {
        var payload = AuthorizationRequestContextSerializer.Encode(MinimalContext());
        var extended = payload.Concat<byte>([0x00]).ToArray();

        AuthorizationRequestContextSerializer.TryDecode(extended, out var decoded).Should().BeFalse(
            "trailing bytes mean the payload is not what this version writes, however cleanly " +
            "the fields ahead of them decoded");
        decoded.Should().BeNull();
    }

    [Fact]
    public void Empty_payload_is_refused()
    {
        AuthorizationRequestContextSerializer.TryDecode([], out var decoded).Should().BeFalse();
        decoded.Should().BeNull();
    }

    [Fact]
    public void Undefined_prompt_value_is_refused()
    {
        // An unchecked cast would put an unrecognised prompt into the interaction stage's
        // decisions, where it reaches protocol behaviour.
        var payload = AuthorizationRequestContextSerializer.Encode(
            MinimalContext() with { Prompts = new HashSet<PromptValue> { PromptValue.Login } });

        var promptByte = Array.LastIndexOf(payload, (byte)PromptValue.Login);
        payload[promptByte] = 200;

        AuthorizationRequestContextSerializer.TryDecode(payload, out _).Should().BeFalse();
    }

    [Fact]
    public void Unbounded_state_round_trips_intact()
    {
        // state is deliberately not length-capped; the guard is on the encoded size, not the
        // parameter, so the format itself must carry whatever a client sends.
        var state = new string('s', 20_000);
        var context = MinimalContext() with { State = state };

        AuthorizationRequestContextSerializer.TryDecode(
            AuthorizationRequestContextSerializer.Encode(context), out var decoded).Should().BeTrue();

        decoded!.State.Should().Be(state);
    }

    [Fact]
    public void Encoding_is_materially_smaller_than_the_field_names_would_be()
    {
        // The reason the format is positional at all. The cookie is re-sent on every request to
        // its path, so the saving is per-request, not once.
        var encoded = AuthorizationRequestContextSerializer.Encode(MinimalContext());

        encoded.Length.Should().BeLessThan(400);
    }

    private static AuthorizationRequestContext MinimalContext() => new()
    {
        Id = "interaction-id",
        ClientId = "test-client",
        RedirectUri = "https://client.example.com/callback",
        Scopes = ["openid"],
        State = null,
        Nonce = "n-0S6_WzA2Mj",
        CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        CodeChallengeMethod = CodeChallengeMethod.S256,
        Prompts = new HashSet<PromptValue>(),
        MaxAge = null,
        IssuedAt = Now,
        ExpiresAt = Now.AddMinutes(30),
    };
}
