using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// The authorization code grant (OAuth 2.1 §4.1.3, RFC 7636 §4.6): redeems the code for the
/// authenticated client, checks what the code was bound to, and issues the tokens.
/// </summary>
/// <remarks>
/// The code is consumed before anything about it is checked. A code whose binding fails —
/// wrong redirect URI, wrong verifier — is burnt by the attempt, so a captured code buys an
/// attacker exactly one guess, and the legitimate client's own exchange then surfaces the theft
/// as a replay.
/// </remarks>
internal sealed class AuthorizationCodeGrant
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly TimeProvider _time;
    private readonly ISanitizingLogger<AuthorizationCodeGrant> _logger;

    public AuthorizationCodeGrant(
        IOptions<AuthorizationServerOptions> options,
        TimeProvider time,
        ISanitizingLogger<AuthorizationCodeGrant> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>Exchanges the request's code for tokens on behalf of <paramref name="client"/>, which has been authenticated.</summary>
    public async Task<IResult> ExchangeAsync(HttpContext context, TokenRequest request, IClientMetadata client)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(client);

        // Resolved from the request's services rather than the constructor: the endpoint that
        // owns this grant is built when the routes are mapped, before startup verification has
        // said whether a store or a signing key ring is registered at all.
        var store = context.RequestServices.GetRequiredService<IAuthorizationCodeStore>();

        // Minted before the redemption so the tombstone written by it carries the family every
        // later replay must revoke — one fresh CSPRNG value per code, never a GUID.
        var familyId = StoreKeyGenerator.Generate();

        AuthorizationCodeRedemptionResult redemption;
        try
        {
            redemption = await store.TryRedeemAsync(request.Code, client.ClientId, familyId, context.RequestAborted).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            _logger.LogError(ex, "Redeeming an authorization code for client {ClientId} failed.", client.ClientId);
            return TokenResponses.ServerError();
        }

        return redemption switch
        {
            AuthorizationCodeRedemptionResult.Redeemed redeemed =>
                await IssueAsync(context, request, client, redeemed.Entry).ConfigureAwait(false),

            AuthorizationCodeRedemptionResult.AlreadyRedeemed replayed =>
                await RefuseReplayAsync(context, client, replayed.FamilyId).ConfigureAwait(false),

            AuthorizationCodeRedemptionResult.ClientMismatch => RefuseMismatchedClient(client),

            AuthorizationCodeRedemptionResult.NotFound => InvalidGrant(),

            _ => throw new InvalidOperationException("Unknown authorization code redemption result."),
        };
    }

    /// <summary>The code is consumed; what it was bound to must now match what the request presents.</summary>
    private async Task<IResult> IssueAsync(HttpContext context, TokenRequest request, IClientMetadata client, AuthorizationCodeEntry entry)
    {
        if (!string.Equals(request.RedirectUri, entry.RedirectUri, StringComparison.Ordinal))
        {
            _logger.LogWarning("Client {ClientId} presented a redirect_uri that differs from the one its authorization code was issued to.", client.ClientId);
            return InvalidGrant();
        }

        if (!PkceVerifier.Verify(request.CodeVerifier, entry.CodeChallenge, entry.CodeChallengeMethod))
        {
            _logger.LogWarning("Client {ClientId} presented a code_verifier that does not match its authorization code's challenge.", client.ClientId);
            return InvalidGrant();
        }

        var now = _time.GetUtcNow();
        var lifetimes = _options.Value.TokenEndpoint;
        var accessTokenExpiresAt = TokenLifetimes.ExpiresAt(now, TokenLifetimes.Effective(client.AccessTokenLifetime, lifetimes.AccessTokenLifetime));
        var idTokenExpiresAt = TokenLifetimes.ExpiresAt(now, TokenLifetimes.Effective(client.IdTokenLifetime, lifetimes.IdTokenLifetime));
        var issuer = _options.Value.Issuer!;

        IssuedToken accessToken;
        IssuedToken idToken;
        try
        {
            // The access token first: the ID token is assembled after it so it can be bound to it.
            accessToken = await Issuer(context, TokenKind.AccessToken).IssueAsync(
                new TokenIssuanceContext(client, TokenKind.AccessToken),
                CodeGrantTokenPayloads.AccessToken(issuer, client, entry, now, accessTokenExpiresAt, jti: StoreKeyGenerator.Generate()),
                context.RequestAborted).ConfigureAwait(false);

            idToken = await Issuer(context, TokenKind.IdToken).IssueAsync(
                new TokenIssuanceContext(client, TokenKind.IdToken),
                CodeGrantTokenPayloads.IdToken(issuer, client, entry, now, idTokenExpiresAt),
                context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Any failure to sign is the server's, and nothing half-issued reaches the client.
            _logger.LogError(ex, "Issuing tokens for client {ClientId} failed.", client.ClientId);
            return TokenResponses.ServerError();
        }

        return TokenResponses.Tokens(new TokenResponse(
            accessToken.Value,
            TokenType: "Bearer",
            ExpiresIn: (long)(accessTokenExpiresAt - now).TotalSeconds,
            idToken.Value,
            Scope: string.Join(' ', entry.Scope)));
    }

    /// <summary>
    /// A code presented twice is a stolen code or a broken client, and either way the family the
    /// first exchange started must not stay alive (RFC 9700 §4.5.3). A revocation the store
    /// cannot perform is logged; the client is refused regardless.
    /// </summary>
    private async Task<IResult> RefuseReplayAsync(HttpContext context, IClientMetadata client, string familyId)
    {
        _logger.LogWarning("Client {ClientId} presented an authorization code that was already redeemed; revoking the family it started.", client.ClientId);

        if (familyId.Length > 0)
        {
            try
            {
                var refreshTokens = context.RequestServices.GetRequiredService<IRefreshTokenStore>();
                await refreshTokens.RevokeFamilyAsync(familyId, context.RequestAborted).ConfigureAwait(false);
            }
            catch (ZeeKayDaStoreException ex)
            {
                _logger.LogError(ex, "Revoking the refresh token family of a replayed authorization code for client {ClientId} failed.", client.ClientId);
            }
        }

        return InvalidGrant();
    }

    private IResult RefuseMismatchedClient(IClientMetadata client)
    {
        _logger.LogWarning("Client {ClientId} presented an authorization code issued to a different client.", client.ClientId);
        return InvalidGrant();
    }

    private static IResult InvalidGrant() =>
        TokenResponses.Error(TokenError.InvalidGrant("The authorization code is invalid, expired, revoked, or was not issued to this client and redirect URI, or the code_verifier does not match."));

    private static ITokenIssuer Issuer(HttpContext context, TokenKind kind) =>
        context.RequestServices.GetRequiredKeyedService<ITokenIssuer>(kind);
}
