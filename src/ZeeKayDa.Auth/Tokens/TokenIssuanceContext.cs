using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What an <see cref="ITokenIssuer"/> is told about the issuance it is performing: the client the
/// token is for and the kind of token being issued. The kind decides the concrete type —
/// <see cref="AccessTokenIssuanceContext"/> or <see cref="IdTokenIssuanceContext"/> — and only
/// those two exist, so what each kind of issuance carries is a property of its type rather than
/// a value that may or may not be set.
/// </summary>
/// <remarks>
/// The hierarchy is closed: the constructor is reachable only from this assembly. The context
/// deliberately carries no tenant field; multi-tenancy is not decided.
/// </remarks>
public abstract class TokenIssuanceContext
{
    private protected TokenIssuanceContext(IClientMetadata client, TokenKind kind)
    {
        ArgumentNullException.ThrowIfNull(client);

        Client = client;
        Kind = kind;
    }

    /// <summary>
    /// The client id and the kind — never a token, which is a bearer credential.
    /// </summary>
    public override string ToString() =>
        $"{GetType().Name} {{ {nameof(Client)} = {Client.ClientId}, {nameof(Kind)} = {Kind} }}";

    /// <summary>
    /// Gets the client the token is issued for. Carried as <see cref="IClientMetadata"/>, not
    /// the full registration, so the issuance path never holds the client's credentials.
    /// </summary>
    public IClientMetadata Client { get; }

    /// <summary>Gets the kind of token being issued.</summary>
    public TokenKind Kind { get; }
}

/// <summary>The issuance of an access token to a client.</summary>
public sealed class AccessTokenIssuanceContext : TokenIssuanceContext
{
    /// <summary>Initializes a context for issuing an access token to <paramref name="client"/>.</summary>
    /// <param name="client">The client the token is issued for.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="client"/> is <see langword="null"/>.
    /// </exception>
    public AccessTokenIssuanceContext(IClientMetadata client)
        : base(client, TokenKind.AccessToken)
    {
    }
}

/// <summary>
/// The issuance of an ID token to a client, bound to the access token issued in the same
/// response through <c>at_hash</c> (OpenID Connect Core §3.1.3.6). An ID token is never issued
/// unbound, so the access token is a required part of the context, not an optional one.
/// </summary>
public sealed class IdTokenIssuanceContext : TokenIssuanceContext
{
    /// <summary>
    /// Initializes a context for issuing an ID token to <paramref name="client"/>, bound to
    /// <paramref name="accessToken"/>.
    /// </summary>
    /// <param name="client">The client the token is issued for.</param>
    /// <param name="accessToken">
    /// The access token the ID token is bound to. Must be of kind
    /// <see cref="TokenKind.AccessToken"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="client"/> or <paramref name="accessToken"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="accessToken"/> is not an access token.
    /// </exception>
    public IdTokenIssuanceContext(IClientMetadata client, IssuedToken accessToken)
        : base(client, TokenKind.IdToken)
    {
        ArgumentNullException.ThrowIfNull(accessToken);

        if (accessToken.Kind != TokenKind.AccessToken)
        {
            throw new ArgumentException(
                $"An ID token is bound to an access token, not to a token of kind {accessToken.Kind}.",
                nameof(accessToken));
        }

        AccessToken = accessToken;
    }

    /// <summary>Gets the access token this ID token is bound to.</summary>
    public IssuedToken AccessToken { get; }
}
