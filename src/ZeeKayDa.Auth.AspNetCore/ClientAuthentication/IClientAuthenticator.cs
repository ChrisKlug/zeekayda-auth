namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Detects and verifies a specific client authentication mechanism at the token endpoint.
/// </summary>
/// <remarks>
/// <para>
/// Implementations MUST be singleton-safe. All credential comparisons MUST be delegated to
/// <see cref="ZeeKayDa.Auth.Clients.IClientSecretHasher"/> implementations — never compare
/// credential strings directly.
/// </para>
/// <para>
/// Custom implementations MUST NOT declare or return <see cref="ZeeKayDa.Auth.Tokens.TokenEndpointAuthMethods.None"/>
/// (<c>"none"</c>) in <see cref="AuthenticationMethods"/> or from <see cref="CanHandle"/>. The
/// <c>none</c> method is reserved for the <see cref="CompositeClientAuthenticator"/> fallback path.
/// </para>
/// </remarks>
public interface IClientAuthenticator
{
    /// <summary>
    /// The set of token endpoint authentication method strings this authenticator can produce.
    /// Used for startup coverage validation against <c>TokenEndpoint.AuthMethodsSupported</c>.
    /// All membership checks MUST use <see cref="System.StringComparer.Ordinal"/> semantics.
    /// </summary>
    IReadOnlySet<string> AuthenticationMethods { get; }

    /// <summary>
    /// Returns <see langword="true"/> if the current request carries authentication material
    /// this authenticator handles, and writes the matched method string to
    /// <paramref name="method"/>. Returns <see langword="false"/> and sets
    /// <paramref name="method"/> to <see langword="null"/> otherwise.
    /// </summary>
    /// <remarks>
    /// MUST be a cheap shape check — no crypto, no database access.
    /// </remarks>
    bool CanHandle(TokenRequestContext context, out string? method);

    /// <summary>
    /// Performs the actual client authentication. Invoked only after
    /// <see cref="CanHandle"/> returned <see langword="true"/> and all composite allowlist
    /// checks have passed. The client in <paramref name="context"/> is guaranteed to exist in
    /// the repository.
    /// </summary>
    /// <param name="context">The authentication context for this request, including the resolved client.</param>
    /// <param name="cancellationToken">Propagates notification that the operation should be cancelled.</param>
    ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context,
        CancellationToken cancellationToken);
}
