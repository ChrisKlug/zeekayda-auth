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
/// <strong>String set comparison invariant.</strong> All <c>IReadOnlySet&lt;string&gt;</c>
/// members (<see cref="RedirectUris"/>, <see cref="PostLogoutRedirectUris"/>,
/// <see cref="AllowedScopes"/>, <see cref="AllowedTokenEndpointAuthMethods"/>) MUST be
/// enumerated with explicit <see cref="System.StringComparer.Ordinal"/> semantics by every
/// consumer. The set's own comparer is NOT trusted — a custom repository may return an entity
/// whose set was constructed with a non-ordinal comparer. This is a security contract, not a
/// suggestion.
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
    /// Membership checks MUST use <see cref="System.StringComparer.Ordinal"/> — do NOT trust the
    /// set's own comparer. Exact ordinal string matching is required by
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
}
