using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What an <see cref="ITokenIssuer"/> is told about the issuance it is performing: the client the
/// token is for, the kind of token being issued, and — for an ID token — the access token issued
/// alongside it.
/// </summary>
/// <param name="Client">
/// The client the token is issued for. Carried as <see cref="IClientMetadata"/>, not the full
/// registration, so the issuance path never holds the client's credentials. An issuer can vary
/// what it issues per client — dispatch by client, or enforce
/// <see cref="IClientMetadata.AllowedSigningAlgorithms"/> — without a repository lookup.
/// </param>
/// <param name="Kind">The kind of token being issued.</param>
/// <param name="AccessToken">
/// The access token issued in the same response, when <paramref name="Kind"/> is
/// <see cref="TokenKind.IdToken"/>; the ID token is bound to it through <c>at_hash</c>
/// (OpenID Connect Core §3.1.3.6). <see langword="null"/> for an access token, and the
/// framework's JWT issuer refuses an ID-token issuance without one.
/// </param>
/// <remarks>
/// The framework constructs the context at the call site, so widening it — as
/// <paramref name="AccessToken"/> did — is an additive change, not a breaking one. That is why it
/// deliberately carries no tenant field today.
/// </remarks>
public readonly record struct TokenIssuanceContext(IClientMetadata Client, TokenKind Kind, IssuedToken? AccessToken = null)
{
    private readonly IClientMetadata? _client =
        Client ?? throw new ArgumentNullException(nameof(Client));

    private readonly TokenKind _kind = Kind;

    private readonly IssuedToken? _accessToken = Companion(Kind, AccessToken);

    /// <summary>Gets the kind of token being issued.</summary>
    /// <exception cref="ArgumentException">
    /// Thrown when the kind set is not <see cref="TokenKind.IdToken"/> while the context carries
    /// an <see cref="AccessToken"/>: a companion belongs to an ID token only.
    /// </exception>
    public TokenKind Kind
    {
        get => _kind;
        init
        {
            Companion(value, _accessToken);
            _kind = value;
        }
    }

    /// <summary>
    /// Gets the access token an ID token is bound to; <see langword="null"/> for an access token.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// Thrown when a token is set on a context whose <see cref="Kind"/> is not
    /// <see cref="TokenKind.IdToken"/>, or when the token set is not an access token: the context
    /// has exactly two valid states, an access token with no companion and an ID token bound to one.
    /// </exception>
    public IssuedToken? AccessToken
    {
        get => _accessToken;
        init => _accessToken = Companion(Kind, value);
    }

    /// <summary>Gets the client the token is issued for.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance is <see langword="default"/>(<see cref="TokenIssuanceContext"/>)
    /// rather than one constructed with a client.
    /// </exception>
    public IClientMetadata Client
    {
        get => _client ?? throw new InvalidOperationException(
            $"{nameof(TokenIssuanceContext)} was default-initialized; a context must be " +
            $"constructed with the client the token is issued for.");
        init => _client = value ?? throw new ArgumentNullException(nameof(value));
    }

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

        builder.Append($"{nameof(Client)} = {_client.ClientId}, {nameof(Kind)} = {Kind}, {nameof(AccessToken)} = {(_accessToken is null ? "none" : "<present>")}");
        return true;
    }

    private static IssuedToken? Companion(TokenKind kind, IssuedToken? accessToken)
    {
        if (accessToken is null)
            return null;

        if (kind != TokenKind.IdToken)
        {
            throw new ArgumentException(
                $"Only an ID token is bound to an access token; a {kind} issuance carries none.");
        }

        if (accessToken.Kind != TokenKind.AccessToken)
        {
            throw new ArgumentException(
                $"An ID token is bound to an access token, not to a token of kind {accessToken.Kind}.");
        }

        return accessToken;
    }
}
