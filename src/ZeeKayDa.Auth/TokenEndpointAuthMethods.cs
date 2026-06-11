namespace ZeeKayDa.Auth;

/// <summary>
/// String constants for the token endpoint authentication methods handled by the ZeeKayDa.Auth
/// framework.
/// </summary>
/// <remarks>
/// <para>
/// <c>IClientRegistration.AllowedTokenEndpointAuthMethods</c> is
/// <c>IReadOnlySet&lt;string&gt;</c> rather than an enum because token endpoint authentication is
/// an open extension point: custom <c>IClientAuthenticator</c> implementations can introduce new
/// methods (such as <c>tls_client_auth</c>) without any framework change. Extension authors should
/// define their own string constants alongside their <c>IClientAuthenticator</c> implementation
/// instead of adding values here.
/// </para>
/// <para>
/// All membership checks against <c>IClientRegistration.AllowedTokenEndpointAuthMethods</c>
/// MUST use <see cref="System.StringComparer.Ordinal"/> semantics — do not rely on the set's own
/// comparer.
/// </para>
/// </remarks>
public static class TokenEndpointAuthMethods
{
    /// <summary>HTTP Basic authentication with a client secret (<c>client_secret_basic</c>).</summary>
    public const string ClientSecretBasic = "client_secret_basic";

    /// <summary>Client secret sent in the request body (<c>client_secret_post</c>).</summary>
    /// <remarks>
    /// Enable only when required for compatibility; request bodies are more likely to appear
    /// in logs than HTTP headers.
    /// </remarks>
    public const string ClientSecretPost = "client_secret_post";

    /// <summary>No client authentication — public clients only (<c>none</c>).</summary>
    /// <remarks>
    /// <c>none</c> is reserved to the composite client authenticator fallback and MUST NOT be
    /// declared or returned by any custom <c>IClientAuthenticator</c> implementation.
    /// </remarks>
    public const string None = "none";
}
