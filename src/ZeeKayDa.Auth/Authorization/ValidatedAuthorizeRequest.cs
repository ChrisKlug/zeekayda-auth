using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// An authorization request that has passed both validation phases. Every value here is safe to
/// act on: the client is validated, the redirect URI is registered, and the scope set is already
/// narrowed to what the client is allowed.
/// </summary>
internal sealed record ValidatedAuthorizeRequest
{
    /// <summary>The validated client registration, credential-free view.</summary>
    public required IClientMetadata Client { get; init; }

    /// <summary>The exact redirect URI the response will be delivered to.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// The effective scopes: <c>requested ∩ Client.AllowedScopes</c>, order-preserving and
    /// de-duplicated. Always contains <c>openid</c>.
    /// </summary>
    public required IReadOnlyList<string> Scopes { get; init; }

    /// <summary>The client's opaque <c>state</c>, echoed byte for byte, or <see langword="null"/>.</summary>
    public required string? State { get; init; }

    /// <summary>The OpenID Connect <c>nonce</c>. Required in v1, so never null or empty.</summary>
    public required string Nonce { get; init; }

    /// <summary>The PKCE code challenge (RFC 7636 §4.3).</summary>
    public required string CodeChallenge { get; init; }

    /// <summary>The PKCE challenge method. Always <see cref="CodeChallengeMethod.S256"/> today.</summary>
    public required CodeChallengeMethod CodeChallengeMethod { get; init; }

    /// <summary>
    /// The recognised <c>prompt</c> values, parsed and syntax-checked. Behavioural handling
    /// (challenge/consent short-circuits) is owned by the interaction stage, not validation.
    /// </summary>
    public required IReadOnlySet<PromptValue> Prompts { get; init; }

    /// <summary>The parsed <c>max_age</c> in seconds, or <see langword="null"/> when absent.</summary>
    public required TimeSpan? MaxAge { get; init; }
}
