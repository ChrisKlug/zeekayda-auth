using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Dispatches token endpoint client authentication to the registered authenticators. Registered as
/// itself, not as an <see cref="IClientAuthenticator"/>, so it never dispatches to itself.
/// </summary>
internal sealed class CompositeClientAuthenticator(
    RegisteredAuthenticators authenticators,
    ValidatedClientResolver clientResolver,
    AdvertisedAuthMethods advertisedAuthMethods,
    ClientSecrets secrets,
    SanitizingLogger<CompositeClientAuthenticator> logger)
{
    /// <summary>
    /// Authenticates the client identified by <paramref name="clientId"/> using the mechanism(s)
    /// detected in the current request.
    /// </summary>
    /// <param name="clientId">The <c>client_id</c> extracted from the token request.</param>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="cancellationToken">Propagates notification that the operation should be cancelled.</param>
    public async ValueTask<AuthenticatedClient> AuthenticateAsync(
        string clientId,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(httpContext);

        var form = await ReadFormIfPresentAsync(httpContext.Request, cancellationToken);

        // RFC 7235 §4.2: no authenticator may see more than one Authorization header.
        if (httpContext.Request.Headers.Authorization.Count > 1)
            return AuthenticatedClient.Refused;

        var answers = AskEveryAuthenticator(new TokenRequestContext { HttpContext = httpContext, ClientId = clientId, Form = form });

        // A credential recognised but not accepted must never fall through to the none method.
        if (answers.Any(answer => answer.Match.IsRefused))
            return RefuseAfterPadding();

        var matches = answers
            .Where(answer => answer.Match.Method is not null)
            .Select(answer => (answer.Registered, Method: answer.Match.Method!))
            .ToList();

        // RFC 6749 §2.3; refused before the repository is read.
        if (matches.Count > 1)
            return AuthenticatedClient.Refused;

        var client = await clientResolver.FindClientWithCredentialsAsync(clientId, cancellationToken);
        if (matches.Count == 0)
            return AuthenticateNone(client);

        var (matched, matchedMethod) = matches[0];

        // A buggy CanHandle may answer a method its authenticator never declared, which startup never checked.
        if (!matched.Performs(matchedMethod) || !IsMethodAllowedByServer(matchedMethod))
            return AuthenticatedClient.Refused;

        // An unknown client and one that does not allow this method are indistinguishable.
        if (client is null || !client.AllowedTokenEndpointAuthMethods.ContainsOrdinal(matchedMethod))
            return RefuseAfterPadding();

        var context = new ClientAuthenticationContext
        {
            HttpContext = httpContext,
            ClientId = clientId,
            Client = client,
            Form = form,
            Method = matchedMethod,
        };
        return Conclude(await TryAuthenticateAsync(matched.Authenticator, context, cancellationToken), client);
    }

    /// <summary>
    /// The form, read asynchronously: <see cref="HttpRequest.Form"/> is synchronous and throws on a
    /// content type the caller chooses.
    /// </summary>
    private static async Task<IFormCollection> ReadFormIfPresentAsync(HttpRequest request, CancellationToken cancellationToken) =>
        request.HasFormContentType
            ? await request.ReadFormAsync(cancellationToken)
            : FormCollection.Empty;

    private List<(RegisteredAuthenticator Registered, ClientAuthenticatorMatch Match)> AskEveryAuthenticator(TokenRequestContext context) =>
        authenticators.All
            .Select(registered => (Registered: registered, Match: TryCanHandle(registered.Authenticator, context)))
            .ToList();

    /// <summary>
    /// The authenticator's result, with a throw logged and treated as a refusal that checked no secret,
    /// so it is padded like any other. A cancellation of the request still propagates.
    /// </summary>
    private async Task<ClientAuthenticationResult?> TryAuthenticateAsync(
        IClientAuthenticator authenticator, ClientAuthenticationContext context, CancellationToken cancellationToken)
    {
        try
        {
            return await authenticator.AuthenticateAsync(context, cancellationToken);
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
        {
            logger.LogError(ex,
                "Authenticator {AuthenticatorType} threw from AuthenticateAsync; treating as a refusal.",
                authenticator.GetType().FullName);
            return null;
        }
    }

    /// <summary>
    /// Accepts, or refuses after padding unless a failed <see cref="ClientSecrets.Verify"/> already
    /// paid for it. A null from a caller-supplied authenticator is a refusal, not a fault to surface.
    /// </summary>
    private AuthenticatedClient Conclude(ClientAuthenticationResult? outcome, IClientWithCredentials client) =>
        outcome switch
        {
            { Authenticated: true } => AuthenticatedClient.Accepted(client),
            not null when outcome.TryClaimPadding() => AuthenticatedClient.Refused,
            _ => RefuseAfterPadding(),
        };

    /// <summary>
    /// The authenticator's match, with a throw or a <see langword="null"/> logged and treated as not
    /// matching rather than failing the request.
    /// </summary>
    private ClientAuthenticatorMatch TryCanHandle(IClientAuthenticator authenticator, TokenRequestContext context)
    {
        try
        {
            if (authenticator.CanHandle(context) is { } match)
                return match;

            logger.LogError(
                "Authenticator {AuthenticatorType} returned null from CanHandle; treating as non-matching.",
                authenticator.GetType().FullName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "Authenticator {AuthenticatorType} threw from CanHandle; treating as non-matching.",
                authenticator.GetType().FullName);
        }

        return ClientAuthenticatorMatch.None;
    }

    private AuthenticatedClient AuthenticateNone(IClientWithCredentials? client)
    {
        // IsPublic is enough: validation guarantees a public client has no credentials and allows only "none".
        if (!IsMethodAllowedByServer(TokenEndpointAuthMethods.None) || client is not { IsPublic: true })
            return RefuseAfterPadding();

        // No padding: success is visible in the response anyway, and client_id is not a secret.
        return AuthenticatedClient.Accepted(client);
    }

    /// <summary>
    /// A refusal that checked no secret, padded to the cost of a wrong one so its timing does not
    /// reveal whether the client exists or how it may authenticate.
    /// </summary>
    private AuthenticatedClient RefuseAfterPadding()
    {
        secrets.Verify(presented: [], stored: []);
        return AuthenticatedClient.Refused;
    }

    private bool IsMethodAllowedByServer(string method) => advertisedAuthMethods.Contains(method);
}
