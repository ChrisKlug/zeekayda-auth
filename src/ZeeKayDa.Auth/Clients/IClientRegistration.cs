using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Represents a registered OAuth 2.0 / OpenID Connect client.
/// </summary>
/// <remarks>
/// <para>
/// Custom <c>IClientRepository</c> implementations may make their own entity types implement
/// this interface directly, avoiding a framework-type mapping step on the hot path.
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
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2">RFC 6749 §2</see> for the
/// public/confidential client distinction.
/// </para>
/// </remarks>
public interface IClientRegistration
{
    /// <summary>The unique identifier for this client.</summary>
    string ClientId { get; }

    /// <summary>
    /// Credentials stored for this client. An empty list indicates a public client.
    /// Use <c>Credentials.OfType&lt;IClientSecret&gt;()</c> to obtain shared-secret credentials.
    /// </summary>
    IReadOnlyList<IClientCredential> Credentials { get; }

    /// <summary>
    /// <see langword="true"/> if this is a public client (no client authentication at the token
    /// endpoint).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This property is declared (non-default interface member) because a silent default value
    /// would convert a configuration omission into a security-relevant runtime behaviour change.
    /// </para>
    /// <para>
    /// Three-way consistency rule (enforced at registration time):
    /// <c>IsPublic ⟺ Credentials.Count == 0 ⟺ AllowedTokenEndpointAuthMethods == { "none" }</c>.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.1">RFC 6749 §2.1</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>.
    /// </para>
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
    /// <remarks>
    /// Membership checks MUST use <see cref="System.StringComparer.Ordinal"/> — do NOT trust the
    /// set's own comparer.
    /// </remarks>
    IReadOnlySet<string> PostLogoutRedirectUris { get; }

    /// <summary>
    /// Scopes this client is permitted to request.
    /// </summary>
    /// <remarks>
    /// Membership checks MUST use <see cref="System.StringComparer.Ordinal"/> — do NOT trust the
    /// set's own comparer.
    /// </remarks>
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
    /// <para>
    /// Membership checks MUST use <see cref="System.StringComparer.Ordinal"/> — do NOT trust the
    /// set's own comparer.
    /// </para>
    /// <para>
    /// The value <c>"none"</c> (see <see cref="TokenEndpointAuthMethods.None"/>) is only valid
    /// for public clients (<see cref="IsPublic"/> == <see langword="true"/>).
    /// </para>
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
    /// <see langword="null"/> means inherit the server-wide
    /// <c>IdTokenOptions.SigningAlgValuesSupported</c>.
    /// </summary>
    /// <remarks>
    /// When non-null, this set MUST be non-empty and MUST be a subset of
    /// <c>IdTokenOptions.SigningAlgValuesSupported</c>. This is validated at startup for
    /// in-memory clients; custom repositories MUST enforce the subset constraint at write time.
    /// </remarks>
    IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms => null;
}
