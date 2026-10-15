using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// The authorization code grant (OAuth 2.1 §4.1.3, RFC 7636 §4.6): redeems the code for the
/// authenticated client, checks what the code was bound to, resolves the subject's claims, and
/// issues the tokens.
/// </summary>
/// <remarks>
/// The code is consumed before anything about it is checked. A code whose binding fails —
/// wrong redirect URI, wrong verifier — is burnt by the attempt, so a captured code buys an
/// attacker exactly one guess, and the legitimate client's own exchange then surfaces the theft
/// as a replay.
/// </remarks>
internal sealed class AuthorizationCodeGrant(
    IOptions<AuthorizationServerOptions> options,
    TimeProvider time,
    GrantClaimsResolver claims,
    SanitizingLogger<AuthorizationCodeGrant> logger)
{
    private readonly GrantClaimsResolver _claims = claims;

    /// <summary>Exchanges the request's code for tokens on behalf of <paramref name="client"/>, which has been authenticated.</summary>
    public async Task<IResult> ExchangeAsync(HttpContext context, TokenRequest request, IClient client)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(client);

        // Before the code is touched, so a PKCE client that forgot its verifier keeps its code.
        if (request.CodeVerifier is null && !PkceRules.MayOmitChallenge(client))
            return TokenResponses.Error(TokenError.InvalidRequest("The code_verifier parameter is required."));

        // Not injected: a missing host registration must surface as the startup verifiers' message, not a DI error.
        var store = context.RequestServices.GetRequiredService<AuthorizationCodeStore>();

        // Before the redemption, so its tombstone carries the family a later replay revokes.
        var familyId = StoreKeyGenerator.Generate();

        AuthorizationCodeRedemptionResult redemption;
        try
        {
            redemption = await store.TryRedeemAsync(request.Code, client.ClientId, familyId, context.RequestAborted).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            logger.LogError(ex, "Redeeming an authorization code for client {ClientId} failed.", client.ClientId);
            return TokenResponses.ServerError();
        }

        return redemption switch
        {
            AuthorizationCodeRedemptionResult.Redeemed redeemed =>
                await IssueAsync(context, request, client, redeemed.Entry, familyId).ConfigureAwait(false),

            AuthorizationCodeRedemptionResult.AlreadyRedeemed replayed =>
                await RefuseReplayAsync(context, client, replayed.FamilyId).ConfigureAwait(false),

            AuthorizationCodeRedemptionResult.ClientMismatch => RefuseMismatchedClient(client),

            AuthorizationCodeRedemptionResult.NotFound => InvalidGrant(),

            _ => throw new InvalidOperationException("Unknown authorization code redemption result."),
        };
    }

    /// <summary>The code is consumed; what it was bound to must now match what the request presents.</summary>
    private async Task<IResult> IssueAsync(HttpContext context, TokenRequest request, IClient client, AuthorizationCodeEntry entry, string familyId)
    {
        if (!string.Equals(request.RedirectUri, entry.RedirectUri, StringComparison.Ordinal))
        {
            logger.LogWarning("Client {ClientId} presented a redirect_uri that differs from the one its authorization code was issued to.", client.ClientId);
            return InvalidGrant();
        }

        // OAuth 2.1 §3.2.4: a malformed exchange, and the code is already burnt.
        if (entry.Pkce is null && request.CodeVerifier is not null)
        {
            logger.LogWarning("Client {ClientId} presented a code_verifier for an authorization code issued without a code_challenge.", client.ClientId);
            return TokenResponses.Error(TokenError.InvalidRequest("The code_verifier parameter was sent, but the authorization request carried no code_challenge."));
        }

        if (!VerifierProvesTheChallengeTheCodeWasIssuedWith(request, entry))
        {
            logger.LogWarning("Client {ClientId} presented a code_verifier that does not match its authorization code's challenge.", client.ClientId);
            return InvalidGrant();
        }

        // Before anything is issued: a reference-token issuer would already have persisted the access token.
        if (!ClientAcceptsSigningAlgorithm(client, context.RequestServices.GetRequiredService<SigningKeyRing>().Current.Algorithm))
        {
            logger.LogError("Client {ClientId} does not allow ID tokens signed with the current signing key's algorithm; nothing was issued.", client.ClientId);
            return TokenResponses.ServerError();
        }

        // Fresh for this issuance, so a subject the provider no longer serves gets nothing.
        var claims = await _claims.ResolveAsync(
            context,
            new ClaimsRequest(client, entry.Sub, entry.Scope, familyId, ClaimsDestination.Tokens)).ConfigureAwait(false);

        return claims switch
        {
            GrantClaimsOutcome.Issue issue => await IssueTokensAsync(context, client, entry, issue).ConfigureAwait(false),
            GrantClaimsOutcome.SubjectInvalid => InvalidGrant(),
            _ => TokenResponses.ServerError(),
        };
    }

    private async Task<IResult> IssueTokensAsync(HttpContext context, IClient client, AuthorizationCodeEntry entry, GrantClaimsOutcome.Issue issue)
    {
        var now = time.GetUtcNow();
        var lifetimes = options.Value.TokenEndpoint;
        var payloads = new CodeGrantTokenPayloads(options.Value.Issuer!, client, entry, now, issue.Claims, issue.ResourceAudience);
        var accessTokenPayload = payloads.AccessToken(
            TokenLifetimes.Effective(client.AccessTokenLifetime, lifetimes.AccessTokenLifetime),
            jti: StoreKeyGenerator.Generate());
        var idTokenPayload = payloads.IdToken(
            TokenLifetimes.Effective(client.IdTokenLifetime, lifetimes.IdTokenLifetime));

        IssuedToken accessToken;
        IssuedToken idToken;
        try
        {
            // The ID token is bound to the access token, so it comes second.
            accessToken = await Issuer(context, TokenKind.AccessToken).IssueAsync(
                new AccessTokenIssuanceContext(client),
                accessTokenPayload.Payload,
                context.RequestAborted).ConfigureAwait(false);

            idToken = await Issuer(context, TokenKind.IdToken).IssueAsync(
                new IdTokenIssuanceContext(client, accessToken),
                idTokenPayload.Payload,
                context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Any failure to sign is the server's, and nothing half-issued reaches the client.
            logger.LogError(ex, "Issuing tokens for client {ClientId} failed.", client.ClientId);
            return TokenResponses.ServerError();
        }

        return TokenResponses.Tokens(new TokenResponse(
            accessToken.Value,
            TokenType: "Bearer",
            ExpiresIn: (long)(accessTokenPayload.ExpiresAt - now).TotalSeconds,
            idToken.Value,
            Scope: string.Join(' ', entry.Scope)));
    }

    /// <summary>
    /// Revokes the family the first exchange started (RFC 9700 §4.5.3). Not cancelled by the client
    /// disconnecting: the revocation is the server's own action.
    /// </summary>
    private async Task<IResult> RefuseReplayAsync(HttpContext context, IClient client, string familyId)
    {
        logger.LogWarning("Client {ClientId} presented an authorization code that was already redeemed; revoking the family it started.", client.ClientId);

        if (familyId.Length > 0)
        {
            try
            {
                var refreshTokens = context.RequestServices.GetRequiredService<RefreshTokenStore>();
                await refreshTokens.RevokeFamilyAsync(familyId, CancellationToken.None).ConfigureAwait(false);
            }
            catch (ZeeKayDaStoreException ex)
            {
                logger.LogError(ex, "Revoking the refresh token family of a replayed authorization code for client {ClientId} failed.", client.ClientId);
            }
        }

        return InvalidGrant();
    }

    private IResult RefuseMismatchedClient(IClient client)
    {
        logger.LogWarning("Client {ClientId} presented an authorization code issued to a different client.", client.ClientId);
        return InvalidGrant();
    }

    /// <summary>
    /// One description for every refusal of the grant, a disabled subject included: which of the
    /// bound values failed, or that the subject is no longer served, is not the client's to learn.
    /// </summary>
    private static IResult InvalidGrant() =>
        TokenResponses.Error(TokenError.InvalidGrant("The authorization code is invalid, expired, revoked, or was not issued to this client and redirect URI, or the code_verifier does not match, or the subject can no longer be issued tokens."));

    /// <summary>
    /// A code issued with a challenge needs the verifier it was derived from, and a missing one
    /// fails like a wrong one; a code issued without a challenge has nothing to prove.
    /// </summary>
    private static bool VerifierProvesTheChallengeTheCodeWasIssuedWith(TokenRequest request, AuthorizationCodeEntry entry) =>
        entry.Pkce is not { } pkce || (request.CodeVerifier is { } verifier && PkceVerifier.Verify(verifier, pkce));

    internal static bool ClientAcceptsSigningAlgorithm(IClient client, SigningAlgorithm algorithm) =>
        client.AllowedSigningAlgorithms is not { } allowed || allowed.Contains(algorithm);

    private static ITokenIssuer Issuer(HttpContext context, TokenKind kind) =>
        context.RequestServices.GetRequiredKeyedService<ITokenIssuer>(kind);
}
