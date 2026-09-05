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
/// The last step of a successful authorization request: mints the authorization code, stores
/// the entry the token endpoint will redeem, discards the interaction, and delivers the code to
/// the client's registered redirect URI.
/// </summary>
/// <remarks>
/// <para>
/// Everything the entry binds comes from the interaction context — the session identifier, the
/// subject, the authentication time, the PKCE challenge, the nonce — never from request input
/// and never minted here. The callers that reach this step have already bound the context to the
/// session the browser holds: the authorization endpoint builds it from the session it just read,
/// a sign-in from the state it just promoted, and the consent service refuses a decision from any
/// other session. Issuance asserts that binding was made rather than reading the session cookie
/// again, which on the sign-in path would see the cookie the request arrived with, not the one
/// this response is writing.
/// </para>
/// <para>
/// The scopes written into the code are those present in all of: the request's effective scopes,
/// the allowed scopes of the registration as it is now, and the scopes the user granted when
/// consent was asked. The registration is the one the caller resolved in this same request, so a
/// client narrowed since the request was accepted issues a narrower code, and one that no longer
/// allows <c>openid</c> ends the request as one that dropped its redirect URI does.
/// </para>
/// </remarks>
internal sealed class AuthorizationCodeIssuer
{
    /// <summary>
    /// What a registration that changed underneath the request tells the user. The same text
    /// the post-authentication dispatch uses for a client that no longer answers, since it is
    /// the same situation: the request was accepted against a registration that no longer
    /// vouches for it.
    /// </summary>
    internal const string ClientNoLongerAnswers =
        "The client that sent the authorization request is no longer registered, or no longer lists its redirect URI.";

    private const string CouldNotIssue = "The authorization server could not issue an authorization code.";

    private readonly AuthorizationFlow _flow;
    private readonly AuthorizationResponses _responses;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISanitizingLogger<AuthorizationCodeIssuer> _logger;

    public AuthorizationCodeIssuer(
        AuthorizationFlow flow,
        AuthorizationResponses responses,
        IOptions<AuthorizationServerOptions> options,
        TimeProvider timeProvider,
        ISanitizingLogger<AuthorizationCodeIssuer> logger)
    {
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(responses);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _flow = flow;
        _responses = responses;
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// Issues the authorization code for <paramref name="requestContext"/> to
    /// <paramref name="client"/>, the registration the caller resolved in this request. Not
    /// terminal — the caller writes the result. The interaction is discarded whichever way this
    /// ends: a request that reached issuance is never resumed.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The context carries no authenticated session, or consent was required and the context
    /// carries no decision. Both are caller errors: every path that reaches issuance binds the
    /// session and records the decision first.
    /// </exception>
    public async Task<IResult> IssueAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        IClientMetadata client)
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
            _flow.Clear(context);
            return _responses.Local(context, AuthorizeRequestErrors.InvalidRequest, ClientNoLongerAnswers);
        }

        var now = _timeProvider.GetUtcNow();
        var entry = new AuthorizationCodeEntry
        {
            ClientId = requestContext.ClientId,
            RedirectUri = requestContext.RedirectUri,
            CodeChallenge = requestContext.CodeChallenge,
            CodeChallengeMethod = requestContext.CodeChallengeMethod,
            Sub = session.Subject,
            Scope = scopes,
            Nonce = requestContext.Nonce,
            AuthTime = session.AuthTime,
            Acr = requestContext.Acr,
            Amr = requestContext.Amr,
            SsoSessionId = session.SessionId,
            InteractionId = requestContext.Id,
            IssuedAt = now,
            ExpiresAt = now + _options.Value.AuthorizationEndpoint.AuthorizationCodeLifetime,
        };

        var code = StoreKeyGenerator.Generate();

        try
        {
            // Resolved from the request's services rather than the constructor, for the reason
            // AuthorizationFlow resolves the client resolver that way: this singleton is built
            // when the endpoints are mapped, before startup verification has said whether a
            // store is registered at all.
            var store = context.RequestServices.GetRequiredService<IAuthorizationCodeStore>();
            await store.StoreAsync(code, entry, context.RequestAborted).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            // Nothing was handed out, so nothing needs revoking. The client learns the server
            // failed; the operator learns which store operation did, through the sanitizing logger.
            _logger.LogError(ex, "Storing the authorization code for client {ClientId} failed.", client.ClientId);

            _flow.Clear(context);
            return _responses.ErrorAtClient(requestContext.RedirectUri, AuthorizeRequestErrors.ServerError, CouldNotIssue, requestContext.State);
        }

        _flow.Clear(context);
        return _responses.CodeAtClient(requestContext.RedirectUri, code, requestContext.State);
    }

    /// <summary>
    /// The session the context was authenticated by. A context without one has not been through
    /// sign-in, and no caller should have reached issuance with it.
    /// </summary>
    private static (string SessionId, string Subject, DateTimeOffset AuthTime) RequireAuthenticated(
        AuthorizationRequestContext requestContext)
    {
        if (requestContext is { SsoSessionId: { } sessionId, Subject: { } subject, AuthTime: { } authTime })
            return (sessionId, subject, authTime);

        throw new InvalidOperationException(
            "Code issuance was reached for an authorization request that has not been authenticated. " +
            "Every path to issuance promotes or reads the SSO session first.");
    }

    /// <summary>
    /// The scopes the code carries: those the request asked for that the registration still
    /// allows, narrowed further by the user's decision when consent was asked.
    /// </summary>
    private static string[] ResolveScopes(AuthorizationRequestContext requestContext, IClientMetadata client)
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
    private static bool ConsentWasRequired(AuthorizationRequestContext requestContext, IClientMetadata client) =>
        client.RequireConsent || requestContext.Prompts.Contains(PromptValue.Consent);
}
