using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What an <see cref="ITokenIssuer"/> is told about the issuance it is performing: the client the
/// token is for, the kind of token being issued, and — for an ID token — the access token issued
/// alongside it.
/// </summary>
/// <remarks>
/// The context has exactly two states and one way to build each: <see cref="ForAccessToken"/>
/// and <see cref="ForIdToken"/>. An access token carries no companion; an ID token is always
/// bound to the access token it hashes into <c>at_hash</c> (OpenID Connect Core §3.1.3.6). No
/// other combination can be constructed. It deliberately carries no tenant field; multi-tenancy
/// is not decided.
/// </remarks>
public readonly record struct TokenIssuanceContext
{
    private readonly IClientMetadata? _client;

    private TokenIssuanceContext(IClientMetadata client, TokenKind kind, IssuedToken? accessToken)
    {
        _client = client;
        Kind = kind;
        AccessToken = accessToken;
    }

    /// <summary>The context for issuing an access token to <paramref name="client"/>.</summary>
    /// <param name="client">
    /// The client the token is issued for. Carried as <see cref="IClientMetadata"/>, not the full
    /// registration, so the issuance path never holds the client's credentials.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="client"/> is <see langword="null"/>.
    /// </exception>
    public static TokenIssuanceContext ForAccessToken(IClientMetadata client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new TokenIssuanceContext(client, TokenKind.AccessToken, accessToken: null);
    }

    /// <summary>
    /// The context for issuing an ID token to <paramref name="client"/>, bound to
    /// <paramref name="accessToken"/>, the access token issued in the same response.
    /// </summary>
    /// <param name="client">The client the token is issued for.</param>
    /// <param name="accessToken">
    /// The access token the ID token is bound to through <c>at_hash</c>. Must be of kind
    /// <see cref="TokenKind.AccessToken"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="client"/> or <paramref name="accessToken"/> is
    /// <see langword="null"/>: an ID token is never issued unbound.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="accessToken"/> is not an access token.
    /// </exception>
    public static TokenIssuanceContext ForIdToken(IClientMetadata client, IssuedToken accessToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(accessToken);

        if (accessToken.Kind != TokenKind.AccessToken)
        {
            throw new ArgumentException(
                $"An ID token is bound to an access token, not to a token of kind {accessToken.Kind}.",
                nameof(accessToken));
        }

        return new TokenIssuanceContext(client, TokenKind.IdToken, accessToken);
    }

    /// <summary>Gets the client the token is issued for.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance is <see langword="default"/>(<see cref="TokenIssuanceContext"/>)
    /// rather than one obtained from <see cref="ForAccessToken"/> or <see cref="ForIdToken"/>.
    /// </exception>
    public IClientMetadata Client => _client ?? throw new InvalidOperationException(
        $"{nameof(TokenIssuanceContext)} was default-initialized; obtain one from " +
        $"{nameof(ForAccessToken)} or {nameof(ForIdToken)}.");

    /// <summary>Gets the kind of token being issued.</summary>
    public TokenKind Kind { get; }

    /// <summary>
    /// Gets the access token an ID token is bound to; <see langword="null"/> exactly when
    /// <see cref="Kind"/> is <see cref="TokenKind.AccessToken"/>.
    /// </summary>
    public IssuedToken? AccessToken { get; }

    // The record's synthesized PrintMembers reads Client, so ToString() on a default instance
    // would throw from the guard above — a debugger watch or a log line is the last place that
    // should fail. Print the default as such instead. The access token is a bearer credential
    // and is never printed.
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        if (_client is null)
        {
            builder.Append("<default>");
            return true;
        }

        builder.Append($"{nameof(Client)} = {_client.ClientId}, {nameof(Kind)} = {Kind}, {nameof(AccessToken)} = {(AccessToken is null ? "none" : "<present>")}");
        return true;
    }
}
