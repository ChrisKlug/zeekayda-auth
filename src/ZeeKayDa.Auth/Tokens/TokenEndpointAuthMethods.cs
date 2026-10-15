namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// String constants for the token endpoint authentication methods handled by the ZeeKayDa.Auth
/// framework.
/// </summary>
/// <remarks>
/// Strings, not an enum, because a custom <c>IClientAuthenticator</c> can add a method, defining its own
/// constant beside it. Compare <c>IClient.AllowedTokenEndpointAuthMethods</c> members with
/// <see cref="System.StringComparer.Ordinal"/>, never the set's own comparer.
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
    /// Reserved to the framework's fallback; a custom <c>IClientAuthenticator</c> must never declare or return it.
    /// </remarks>
    public const string None = "none";
}
