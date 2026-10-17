using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>An authorization request that passed both validation phases, safe to act on.</summary>
internal sealed record ValidatedAuthorizeRequest
{
    /// <summary>The validated client registration, credential-free view.</summary>
    public required IClient Client { get; init; }

    /// <summary>The exact redirect URI the response will be delivered to.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>The effective scopes, <c>requested ∩ Client.AllowedScopes</c>, always including <c>openid</c>.</summary>
    public required IReadOnlyList<string> Scopes { get; init; }

    /// <summary>The client's opaque <c>state</c>, echoed byte for byte, or <see langword="null"/>.</summary>
    public required string? State { get; init; }

    /// <summary>The OpenID Connect <c>nonce</c>, or <see langword="null"/> when the request carried none; never empty.</summary>
    public required string? Nonce { get; init; }

    /// <summary>The PKCE binding (RFC 7636 §4.3), or <see langword="null"/> when the client may omit it and did.</summary>
    public required PkceChallenge? Pkce { get; init; }

    /// <summary>The recognised <c>prompt</c> values, for the interaction stage to act on.</summary>
    public required IReadOnlySet<PromptValue> Prompts { get; init; }

    /// <summary>The parsed <c>max_age</c> in seconds, or <see langword="null"/> when absent.</summary>
    public required TimeSpan? MaxAge { get; init; }

    /// <summary>The client's well-formed <c>login_hint</c>, or <see langword="null"/> when blank. A hint, never an identity.</summary>
    public required string? LoginHint { get; init; }

    /// <summary>
    /// The subject a valid <c>id_token_hint</c> names, or <see langword="null"/> without one: only a
    /// session for this user may answer the request (OIDC Core §3.1.2.2).
    /// </summary>
    public required string? RequiredSubject { get; init; }
}
