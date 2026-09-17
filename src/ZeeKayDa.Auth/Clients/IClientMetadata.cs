using System.Collections.Frozen;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Everything the framework knows about a registered client except its credentials.
/// </summary>
/// <remarks>
/// <para>
/// This is the view handed to code that must decide <em>what</em> to issue a client without ever
/// needing to authenticate it — <c>ITokenIssuer</c> above all. Client authentication takes
/// <see cref="IClientRegistration"/>, which adds <see cref="IClientRegistration.Credentials"/>;
/// everything else takes this. A downcast still reaches the credentials, so this is a guardrail
/// rather than a boundary: its value is that the default path does not carry secrets, so code that
/// touches them has to visibly reach for them.
/// </para>
/// <para>
/// <strong>String set comparison invariant.</strong> The values in <see cref="RedirectUris"/>,
/// <see cref="PostLogoutRedirectUris"/>, <see cref="AllowedScopes"/> and
/// <see cref="AllowedTokenEndpointAuthMethods"/> are compared with
/// <see cref="System.StringComparer.Ordinal"/>, never with the comparer the set was built with, and
/// counted by what the set enumerates, never by its <c>Count</c>. The framework guarantees both for
/// every registration it hands out — to its own endpoints, and to a host's token issuer through
/// <c>TokenIssuanceContext.Client</c>: each is a copy whose four sets were rebuilt with
/// <see cref="System.StringComparer.Ordinal"/> from what the store's sets enumerated, whatever
/// comparer the store used. Framework code compares explicitly anyway, so a code path that one day
/// reaches a registration without the copy stays safe.
/// </para>
/// <para>
/// Code that reads a registration straight from an <see cref="IClientRepository"/> gets no such
/// guarantee, because a custom repository may build a set with a case-insensitive comparer or one
/// whose <c>Count</c> differs from what it enumerates. Such code — an
/// <see cref="IClientRegistrationValidator"/>, which a custom repository calls on its own entity at
/// write time, the repository's own code, or host code that resolves the repository itself — MUST
/// compare with explicit <see cref="System.StringComparer.Ordinal"/> and count by enumerating. This is a security
/// contract, not a suggestion: a case-insensitive redirect URI or authentication method allowlist
/// accepts values that were never registered.
/// </para>
/// </remarks>
public interface IClientMetadata
{
    /// <summary>The unique identifier for this client.</summary>
    string ClientId { get; }

    /// <summary>
    /// <see langword="true"/> if this is a public client (no client authentication at the token
    /// endpoint).
    /// </summary>
    /// <remarks>
    /// Declared (non-default interface member) because a silent default value would convert a
    /// configuration omission into a security-relevant runtime behaviour change. Three-way
    /// consistency rule: a client is public if and only if it has no entries in
    /// <see cref="IClientRegistration.Credentials"/>, and if and only if
    /// <see cref="AllowedTokenEndpointAuthMethods"/> is exactly <c>{ "none" }</c>. Enforced at
    /// registration time by <see cref="IClientRegistrationValidator"/> — a custom
    /// <see cref="IClientRepository"/> that never runs the validator enforces nothing, and MUST
    /// uphold the rule itself at write time.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.1">RFC 6749 §2.1</see>.
    /// </remarks>
    bool IsPublic { get; }

    /// <summary>
    /// Permitted redirect URIs for the authorization code flow.
    /// </summary>
    /// <remarks>
    /// Matched with <see cref="System.StringComparer.Ordinal"/>, as
    /// <see cref="IClientMetadata"/>'s string-set comparison invariant describes. Exact string
    /// matching is required by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>.
    /// </remarks>
    IReadOnlySet<string> RedirectUris { get; }

    /// <summary>
    /// Permitted post-logout redirect URIs. May be empty.
    /// </summary>
    /// <remarks>See <see cref="IClientMetadata"/>'s string-set comparison invariant.</remarks>
    IReadOnlySet<string> PostLogoutRedirectUris { get; }

    /// <summary>
    /// Scopes this client is permitted to request.
    /// </summary>
    /// <remarks>See <see cref="IClientMetadata"/>'s string-set comparison invariant.</remarks>
    IReadOnlySet<string> AllowedScopes { get; }

    /// <summary>OAuth 2.0 grant types this client is permitted to use.</summary>
    IReadOnlySet<GrantType> AllowedGrantTypes { get; }

    /// <summary>Response types this client is permitted to request.</summary>
    IReadOnlySet<ResponseType> AllowedResponseTypes { get; }

    /// <summary>Response modes this client is permitted to request.</summary>
    IReadOnlySet<ResponseMode> AllowedResponseModes { get; }

    /// <summary>
    /// Token endpoint authentication methods this client is permitted to use.
    /// </summary>
    /// <remarks>
    /// See <see cref="IClientMetadata"/>'s string-set comparison invariant. The value
    /// <c>"none"</c> (see <see cref="TokenEndpointAuthMethods.None"/>) is only valid for public
    /// clients (<see cref="IsPublic"/> == <see langword="true"/>).
    /// </remarks>
    IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; }

    /// <summary>
    /// OpenID Connect <c>prompt</c> values this client is permitted to request.
    /// An empty set means all defined <see cref="PromptValue"/> values are permitted.
    /// </summary>
    /// <remarks>
    /// The default interface implementation returns an empty set (all prompt values permitted),
    /// which is forward-compatible when new <see cref="PromptValue"/> members are added.
    /// An explicit full-set default would be a forward-compatibility trap.
    /// </remarks>
    IReadOnlySet<PromptValue> AllowedPromptValues => FrozenSet<PromptValue>.Empty;

    /// <summary>
    /// When <see langword="true"/>, the framework may include ZeeKayDa-specific extended error
    /// codes (<c>zkd_error</c>) in token endpoint responses for this client.
    /// </summary>
    /// <remarks>
    /// Even with extended error codes enabled, the <c>zkd_error</c> value for
    /// <c>invalid_client</c> MUST NOT distinguish an unknown <c>client_id</c> from a wrong
    /// credential (client enumeration non-disclosure constraint).
    /// </remarks>
    bool EnableZkdErrorCodes { get; }

    /// <summary>
    /// The name shown to the user where the framework hands a host page the client's identity —
    /// the consent page above all. <see langword="null"/> (the default) when the registration
    /// carries none; the page then falls back to <see cref="ClientId"/>.
    /// </summary>
    string? DisplayName => null;

    /// <summary>
    /// Whether the user must consent on the host's consent page before an authorization code is
    /// issued to this client. Defaults to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Consent is what lets a user notice an authorization request they never started: a
    /// malicious or compromised client can navigate a victim to a valid request of its own and
    /// collect the code the victim's sign-in produces, and the consent page is the only thing
    /// between that sign-in and the code. Setting this to <see langword="false"/> removes that
    /// protection for this client, which is a deliberate choice for an operator's own
    /// first-party applications and nothing else. It is a default interface member because
    /// requiring consent is what a registration means unless it says otherwise.
    /// </remarks>
    bool RequireConsent => true;

    /// <summary>
    /// Whether a sign-out this client starts may end the user's session without asking them
    /// first. Defaults to <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// Even when <see langword="true"/>, the question is skipped only for a request carrying a
    /// valid <c>id_token_hint</c> issued to this client for the user signed in to the browser; any
    /// other sign-out is confirmed. An ID token is not a secret — it passes through the browser
    /// and the client's own logs — so skipping the question lets anyone holding one of the user's
    /// ID tokens for this client sign them out. Set it only for an operator's own first-party
    /// applications. It is a default interface member because asking is what a registration
    /// means unless it says otherwise.
    /// </remarks>
    bool SkipLogoutConfirmation => false;

    /// <summary>
    /// Whether this client may omit PKCE from an authorization request and rely on the OpenID
    /// Connect <c>nonce</c> for code-injection protection instead. Defaults to
    /// <see langword="false"/>, and is only valid on a confidential client.
    /// </summary>
    /// <remarks>
    /// PKCE is enforced for every client unless the client is confidential and the operator has
    /// reasonable assurance it implements the <c>nonce</c> check properly (OAuth 2.1 §7.5.1.1,
    /// RFC 9700 §2.1.1). This opt-in is that assurance; PKCE stays recommended even then, and a
    /// challenge the client does send is enforced as for any other client.
    /// </remarks>
    bool AllowNonceInsteadOfPkce => false;

    /// <summary>
    /// JWS signing algorithms permitted for ID tokens issued to this client.
    /// <see langword="null"/> means inherit the server's advertised set.
    /// </summary>
    /// <remarks>
    /// The advertised set is the distinct algorithms of the published signing key set, narrowed by
    /// <c>IdTokenOptions.AdvertisedSigningAlgorithms</c> when that filter is configured — the same
    /// set the discovery document publishes as <c>id_token_signing_alg_values_supported</c>. When
    /// non-null, this set MUST be non-empty and MUST be a subset of it. This is validated at startup
    /// for in-memory clients; custom repositories MUST enforce the subset constraint at write time.
    /// </remarks>
    IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms => null;

    /// <summary>
    /// The lifetime of access tokens issued to this client, or <see langword="null"/> (the
    /// default) to use the server-wide <c>TokenEndpointOptions.AccessTokenLifetime</c>.
    /// </summary>
    /// <remarks>
    /// When non-null, MUST be greater than <see cref="TimeSpan.Zero"/>; the registration
    /// validator rejects it otherwise. No upper bound is enforced.
    /// </remarks>
    TimeSpan? AccessTokenLifetime => null;

    /// <summary>
    /// The lifetime of ID tokens issued to this client, or <see langword="null"/> (the default)
    /// to use the server-wide <c>TokenEndpointOptions.IdTokenLifetime</c>.
    /// </summary>
    /// <remarks>
    /// When non-null, MUST be greater than <see cref="TimeSpan.Zero"/>; the registration
    /// validator rejects it otherwise. No upper bound is enforced.
    /// </remarks>
    TimeSpan? IdTokenLifetime => null;

    /// <summary>
    /// Claim types added to the ID token of every grant to this client, beyond what the granted
    /// scopes unlock. Empty by default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A selector, not a source: a type named here still has to come back from the host's
    /// <c>IClaimsProvider</c> to appear anywhere. Additions only widen; removal is
    /// <see cref="AllowedScopes"/>. An addition may not name a claim that any registered scope
    /// unlocks in any destination, so a consent-bearing claim such as <c>email</c> can only
    /// arrive through its scope; the framework checks that on every grant it selects claims for,
    /// and a colliding registration is answered <c>server_error</c>. Compared with
    /// <see cref="System.StringComparer.Ordinal"/>, whatever the collection's own comparer.
    /// </para>
    /// </remarks>
    IReadOnlyCollection<string> AdditionalIdTokenClaims => [];

    /// <summary>
    /// Claim types added to the userinfo response of every grant to this client, beyond what the
    /// granted scopes unlock. Empty by default; the rules of <see cref="AdditionalIdTokenClaims"/> apply.
    /// </summary>
    IReadOnlyCollection<string> AdditionalUserInfoClaims => [];

    /// <summary>
    /// Claim types added to the access token of every grant to this client, beyond what the
    /// granted scopes unlock. Empty by default; the rules of <see cref="AdditionalIdTokenClaims"/> apply.
    /// </summary>
    IReadOnlyCollection<string> AdditionalAccessTokenClaims => [];
}
