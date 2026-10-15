using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The last step of a successful authorization request: claims the interaction, stores the code
/// entry the token endpoint redeems, discards the interaction, and delivers the code.
/// </summary>
/// <remarks>
/// Everything the entry binds comes from the interaction context, never from request input. The
/// session binding is asserted, not re-read: on the sign-in path the cookie the request arrived
/// with is not the one this response writes.
/// </remarks>
internal sealed class AuthorizationCodeIssuer(
    AuthorizationFlow flow,
    AuthorizationResponses responses,
    IOptions<AuthorizationServerOptions> options,
    SanitizingLogger<AuthorizationCodeIssuer> logger)
{
    /// <summary>What the user is told when the client's registration no longer vouches for the request.</summary>
    internal const string ClientNoLongerAnswers =
        "The client that sent the authorization request is no longer registered, or no longer lists its redirect URI.";

    private const string CouldNotIssue = "The authorization server could not issue an authorization code.";

    private const string OpenIdNoLongerAllowed = "The client is no longer allowed the openid scope.";

    /// <summary>
    /// Issues the code to <paramref name="client"/> as resolved in this request, discarding the
    /// interaction whichever way it ends. Not terminal.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The context carries no authenticated session, or consent was required and the context
    /// carries no decision. Both are caller errors: every path that reaches issuance binds the
    /// session and records the decision first.
    /// </exception>
    /// <exception cref="NothingToContinueException">
    /// Another response completed the interaction first, or it expired while this response was
    /// being prepared.
    /// </exception>
    public async Task<IResult> IssueAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        IClient client)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(client);

        // The response carries the code; a cached copy is a stolen one.
        context.Response.Headers.CacheControl = "no-store";

        var session = RequireAuthenticated(requestContext);
        var scopes = ResolveScopes(requestContext, client);

        if (!scopes.Contains(StandardScopes.OpenId.Name, StringComparer.Ordinal))
        {
            await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
            return responses.ErrorAtClient(requestContext.RedirectUri, AuthorizeRequestErrors.InvalidScope, OpenIdNoLongerAllowed, requestContext.State);
        }

        // Not from the constructor: this singleton is built at mapping, before startup verification.
        var store = context.RequestServices.GetRequiredService<AuthorizationCodeStore>();

        string code;
        try
        {
            var now = await flow.ClaimCompletionAsync(context, requestContext).ConfigureAwait(false);

            code = StoreKeyGenerator.Generate();
            await store.StoreAsync(code, BuildEntry(requestContext, session, scopes, now), context.RequestAborted).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            // Nothing was handed out, so nothing needs revoking.
            logger.LogError(ex, "Storing the authorization code for client {ClientId} failed.", client.ClientId);

            await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
            return responses.ErrorAtClient(requestContext.RedirectUri, AuthorizeRequestErrors.ServerError, CouldNotIssue, requestContext.State);
        }

        await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        return responses.CodeAtClient(requestContext.RedirectUri, code, requestContext.State);
    }

    /// <summary>The entry the token endpoint will redeem.</summary>
    private AuthorizationCodeEntry BuildEntry(
        AuthorizationRequestContext requestContext,
        (string SessionId, string Subject, DateTimeOffset AuthTime) session,
        string[] scopes,
        DateTimeOffset now) =>
        new()
        {
            ClientId = requestContext.ClientId,
            RedirectUri = requestContext.RedirectUri,
            Pkce = requestContext.Pkce,
            Sub = session.Subject,
            Scope = scopes,
            Nonce = requestContext.Nonce,
            AuthTime = session.AuthTime,
            Acr = requestContext.Acr,
            Amr = requestContext.Amr,
            SsoSessionId = session.SessionId,
            InteractionId = requestContext.Id,
            IssuedAt = now,
            ExpiresAt = now + options.Value.AuthorizationEndpoint.AuthorizationCodeLifetime,
        };

    /// <summary>The session the context was authenticated by.</summary>
    private static (string SessionId, string Subject, DateTimeOffset AuthTime) RequireAuthenticated(
        AuthorizationRequestContext requestContext)
    {
        if (requestContext is { SsoSessionId: { } sessionId, Subject: { } subject, AuthTime: { } authTime })
            return (sessionId, subject, authTime);

        throw new InvalidOperationException(
            "Code issuance was reached for an authorization request that has not been authenticated. " +
            "Every path to issuance promotes or reads the SSO session first.");
    }

    /// <summary>The requested scopes the registration still allows and the user granted, if asked.</summary>
    private static string[] ResolveScopes(AuthorizationRequestContext requestContext, IClient client)
    {
        var granted = requestContext.GrantedScopes;

        if (granted is null && ConsentWasRequired(requestContext, client))
        {
            throw new InvalidOperationException(
                "Code issuance was reached for a client that requires consent, but the request carries no " +
                "consent decision. A decision is recorded by the consent page before issuance.");
        }

        return requestContext.Scopes
            .Where(scope => client.AllowedScopes.Contains(scope, StringComparer.Ordinal))
            .Where(scope => granted is null || granted.Contains(scope, StringComparer.Ordinal))
            .ToArray();
    }

    /// <summary>Whether this request had to go through the consent page: the registration says so, or the request asked.</summary>
    private static bool ConsentWasRequired(AuthorizationRequestContext requestContext, IClient client) =>
        client.RequireConsent || requestContext.Prompts.Contains(PromptValue.Consent);
}
