using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Everything the framework knows about a registered client except its credentials.
/// </summary>
/// <remarks>
/// <para>
/// The view handed to code that decides <em>what</em> to issue a client; client authentication takes
/// <see cref="IClientWithCredentials"/>. A downcast still reaches the credentials, so this is a
/// guardrail: code touching secrets has to visibly reach for them.
/// </para>
/// <para>
/// <strong>String set comparison invariant.</strong> <see cref="RedirectUris"/>,
/// <see cref="PostLogoutRedirectUris"/>, <see cref="AllowedScopes"/> and
/// <see cref="AllowedTokenEndpointAuthMethods"/> are compared with <see cref="System.StringComparer.Ordinal"/>,
/// never the set's own comparer, and counted by enumerating, never by <c>Count</c>. Every registration
/// the framework hands out is a copy with those sets rebuilt that way.
/// </para>
/// <para>
/// Code reading a registration straight from an <see cref="IClientRepository"/> gets no such copy and
/// MUST compare ordinally and count by enumerating. This is a security contract: a case-insensitive redirect URI or auth method
/// allowlist accepts values that were never registered.
/// </para>
/// </remarks>
public interface IClient
{
    /// <summary>The unique identifier for this client.</summary>
    string ClientId { get; }

    /// <summary>
    /// <see langword="true"/> if this is a public client (no client authentication at the token
    /// endpoint).
    /// </summary>
    /// <remarks>
    /// Declared, never computed from the credentials, so a public client that forgets to say so fails
    /// validation loudly. A client is public if and only if it has no
    /// <see cref="IClientWithCredentials.Secrets"/>, and if and only if
    /// <see cref="AllowedTokenEndpointAuthMethods"/> is exactly <c>{ "none" }</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.1">RFC 6749 §2.1</see>).
    /// </remarks>
    bool IsPublic => ClientDefaults.IsPublic;

    /// <summary>
    /// Permitted redirect URIs for the authorization code flow.
    /// </summary>
    /// <remarks>
    /// Matched exactly and ordinally
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>).
    /// </remarks>
    IReadOnlySet<string> RedirectUris => ClientDefaults.RedirectUris;

    /// <summary>
    /// Permitted post-logout redirect URIs. May be empty.
    /// </summary>
    /// <remarks>See <see cref="IClient"/>'s string-set comparison invariant.</remarks>
    IReadOnlySet<string> PostLogoutRedirectUris => ClientDefaults.PostLogoutRedirectUris;

    /// <summary>
    /// Scopes this client is permitted to request.
    /// </summary>
    /// <remarks>See <see cref="IClient"/>'s string-set comparison invariant.</remarks>
    IReadOnlySet<string> AllowedScopes => ClientDefaults.AllowedScopes;

    /// <summary>OAuth 2.0 grant types this client is permitted to use.</summary>
    /// <remarks>
    /// Must be non-empty and a subset of the server's
    /// <see cref="AuthorizationServerOptions.GrantTypesSupported"/>; registration fails otherwise.
    /// </remarks>
    IReadOnlySet<GrantType> AllowedGrantTypes => ClientDefaults.AllowedGrantTypes;

    /// <summary>Response types this client is permitted to request.</summary>
    /// <remarks>
    /// Must be a subset of the server's <see cref="ResponseOptions.TypesSupported"/>, and non-empty
    /// when <see cref="AllowedGrantTypes"/> contains <see cref="GrantType.AuthorizationCode"/>;
    /// registration fails otherwise.
    /// </remarks>
    IReadOnlySet<ResponseType> AllowedResponseTypes => ClientDefaults.AllowedResponseTypes;

    /// <summary>Response modes this client is permitted to request.</summary>
    /// <remarks>
    /// Must be a subset of the server's <see cref="ResponseOptions.ModesSupported"/>, and non-empty
    /// when <see cref="AllowedGrantTypes"/> contains <see cref="GrantType.AuthorizationCode"/>;
    /// registration fails otherwise.
    /// </remarks>
    IReadOnlySet<ResponseMode> AllowedResponseModes => ClientDefaults.AllowedResponseModes;

    /// <summary>
    /// Token endpoint authentication methods this client is permitted to use.
    /// </summary>
    /// <remarks>
    /// <c>"none"</c> (<see cref="TokenEndpointAuthMethods.None"/>) is valid only for a public client.
    /// </remarks>
    IReadOnlySet<string> AllowedTokenEndpointAuthMethods => ClientDefaults.AllowedTokenEndpointAuthMethods(IsPublic);

    /// <summary>
    /// OpenID Connect <c>prompt</c> values this client is permitted to request.
    /// An empty set means all defined <see cref="PromptValue"/> values are permitted.
    /// </summary>
    /// <remarks>
    /// Empty by default, so a <see cref="PromptValue"/> added later is permitted too.
    /// </remarks>
    IReadOnlySet<PromptValue> AllowedPromptValues => ClientDefaults.AllowedPromptValues;

    /// <summary>
    /// When <see langword="true"/>, an authorization error redirect that answers
    /// <c>access_denied</c> for this client also carries a <c>zkd_error</c> sub-code saying which
    /// refusal it was: <c>login_cancelled</c>, <c>consent_declined</c>, <c>provider_declined</c> or
    /// <c>account_refused</c>.
    /// </summary>
    /// <remarks>
    /// The standard <c>error</c> is unchanged, and a client that does not know the parameter ignores it
    /// (RFC 6749 §4.1.2). A code says only what the user did or already knows, never whether an account
    /// exists, which credential was wrong, or which provider was used. The token endpoint never sends one.
    /// </remarks>
    bool EnableZkdErrorCodes => ClientDefaults.EnableZkdErrorCodes;

    /// <summary>
    /// The name shown to the user where the framework hands a host page the client's identity —
    /// the consent page above all. <see langword="null"/> (the default) when the registration
    /// carries none; the page then falls back to <see cref="ClientId"/>.
    /// </summary>
    string? DisplayName => ClientDefaults.DisplayName;

    /// <summary>
    /// The client's <c>initiate_login_uri</c> (OpenID Connect Core §4): where the browser is sent, with
    /// <c>iss</c>, to start a new sign-in when a page is submitted for an interaction that no longer exists.
    /// <see langword="null"/> (the default) sends the user to the host's error page instead.
    /// </summary>
    /// <remarks>
    /// An absolute <c>https</c> URI with no fragment or userinfo; startup fails otherwise. The
    /// client must treat a request to it only as a prompt to start a sign-in at the issuer named by
    /// <c>iss</c>, and only for an issuer it already trusts.
    /// </remarks>
    string? InitiateLoginUri => ClientDefaults.InitiateLoginUri;

    /// <summary>
    /// Whether the user must consent on the host's consent page before an authorization code is
    /// issued to this client. Defaults to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Consent lets a user notice a request they never started: a malicious client can send a victim to a
    /// valid request of its own and collect the code their sign-in produces. <see langword="false"/> removes
    /// that protection, so set it only for an operator's own first-party applications.
    /// </remarks>
    bool RequireConsent => ClientDefaults.RequireConsent;

    /// <summary>
    /// Whether a sign-out this client starts may end the user's session without asking them
    /// first. Defaults to <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// Even then, only a request with a valid <c>id_token_hint</c> issued to this client for the signed-in
    /// user skips the question. An ID token is not a secret, so anyone holding one can sign the user out:
    /// set it only for an operator's own first-party applications.
    /// </remarks>
    bool SkipLogoutConfirmation => ClientDefaults.SkipLogoutConfirmation;

    /// <summary>
    /// Whether this client must send a PKCE <c>code_challenge</c> with every authorization request.
    /// Defaults to <see langword="true"/>; only a confidential client may be registered with
    /// <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// <see langword="false"/> is the operator's assurance that the client checks <c>nonce</c> properly
    /// (OAuth 2.1 §7.5.1.1, RFC 9700 §2.1.1), and is not checked per request: a code issued with neither a
    /// challenge nor a <c>nonce</c> has nothing protecting it from injection (RFC 9700 §4.5). A challenge the
    /// client does send is still enforced. On a public client it fails startup.
    /// </remarks>
    bool RequirePkce => ClientDefaults.RequirePkce;

    /// <summary>
    /// JWS signing algorithms this client accepts for its ID tokens. <see langword="null"/> accepts
    /// whatever the server signs with.
    /// </summary>
    /// <remarks>
    /// When non-null, MUST be non-empty, defined values only, and contain the one algorithm the server signs
    /// with; the validator enforces this. Any other entry has no effect and is warned about once.
    /// </remarks>
    IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms => ClientDefaults.AllowedSigningAlgorithms;

    /// <summary>
    /// The lifetime of access tokens issued to this client, or <see langword="null"/> (the
    /// default) to use the server-wide <c>TokenEndpointOptions.AccessTokenLifetime</c>.
    /// </summary>
    /// <remarks>
    /// When non-null, MUST be greater than <see cref="TimeSpan.Zero"/>; the registration
    /// validator rejects it otherwise. No upper bound is enforced.
    /// </remarks>
    TimeSpan? AccessTokenLifetime => ClientDefaults.AccessTokenLifetime;

    /// <summary>
    /// The lifetime of ID tokens issued to this client, or <see langword="null"/> (the default)
    /// to use the server-wide <c>TokenEndpointOptions.IdTokenLifetime</c>.
    /// </summary>
    /// <remarks>
    /// When non-null, MUST be greater than <see cref="TimeSpan.Zero"/>; the registration
    /// validator rejects it otherwise. No upper bound is enforced.
    /// </remarks>
    TimeSpan? IdTokenLifetime => ClientDefaults.IdTokenLifetime;

    /// <summary>
    /// Claim types added to the ID token of every grant to this client, beyond what the granted
    /// scopes unlock. Empty by default.
    /// </summary>
    /// <remarks>
    /// A selector, not a source: the type still has to come back from the host's <c>IClaimsProvider</c>.
    /// Additions only widen. One may not name a claim any registered scope unlocks, so a consent-bearing claim
    /// such as <c>email</c> arrives only through its scope; a colliding registration is answered
    /// <c>server_error</c>. Compared ordinally, whatever the collection's own comparer.
    /// </remarks>
    IReadOnlySet<string> AdditionalIdTokenClaims => ClientDefaults.AdditionalClaims;

    /// <summary>
    /// Claim types added to the userinfo response of every grant to this client, beyond what the
    /// granted scopes unlock. Empty by default; the rules of <see cref="AdditionalIdTokenClaims"/> apply.
    /// </summary>
    IReadOnlySet<string> AdditionalUserInfoClaims => ClientDefaults.AdditionalClaims;

    /// <summary>
    /// Claim types added to the access token of every grant to this client, beyond what the
    /// granted scopes unlock. Empty by default; the rules of <see cref="AdditionalIdTokenClaims"/> apply.
    /// </summary>
    IReadOnlySet<string> AdditionalAccessTokenClaims => ClientDefaults.AdditionalClaims;
}
