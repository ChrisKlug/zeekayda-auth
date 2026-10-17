using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The end-session endpoint (<c>/connect/endsession</c>, GET and POST per OpenID Connect
/// RP-Initiated Logout 1.0 §2), and, for a host without a logout page of its own, the
/// confirmation route behind it.
/// </summary>
/// <remarks>
/// <para>
/// Nothing a sign-out sends is refused. A parameter that fails to validate is ignored, and the
/// worst a bad request can do is land the user on a confirmation or signed-out page instead of back
/// at the client. An <c>id_token_hint</c> that fails to validate is an error in the request, so
/// the user is not sent back to the client at all (§4).
/// </para>
/// <para>
/// A sign-out ends one account: the one a valid <c>id_token_hint</c> names, or else the client's
/// own — the one last signed in to or picked for it. The user is signed out without being asked only when there is
/// nothing to end — no account at all, or none for the hinted user — or when a valid hint names a
/// signed-in account and its client opted out of the question with <c>SkipLogoutConfirmation</c>.
/// Everything else is confirmed first (§2), and the confirmation can end every account instead.
/// </para>
/// </remarks>
internal sealed class EndSessionEndpoint(
    IOptions<AuthorizationServerOptions> options,
    SsoSession session,
    LogoutRequestStore requests,
    EndSessionResponses responses,
    SanitizingLogger<EndSessionEndpoint> logger) : IZeeKayDaEndpoint
{
    /// <summary>
    /// The longest <c>state</c> echoed to a client — far above what a relying party sends. A
    /// sign-out carrying a longer one is not sent back to the client at all, rather than sent back
    /// with a <c>state</c> the client cannot match.
    /// </summary>
    internal const int MaxStateLength = 2048;

    private const string DefaultPath = "connect/endsession";
    private const string ConfirmSuffix = "/confirm";

    private readonly SsoSession _session = session;

    /// <inheritdoc/>
    /// <remarks>Served only with the authorization code grant, the only flow that signs anyone in.</remarks>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        if (!options.Value.GrantTypesSupported.Contains(GrantType.AuthorizationCode))
            return;

        var endpointUri = PublishedUri();

        Delegate handler = HandleAsync;
        endpoints.MapMethods(endpointUri.AbsolutePath, [HttpMethods.Get, HttpMethods.Post], handler)
            .RequireIssuerHost(endpointUri)
            .ExemptFromHostAuthorization();

        if (options.Value.EndSessionEndpoint.LogoutPath is not null)
            return;

        Delegate confirm = ConfirmAsync;
        endpoints.MapMethods(ConfirmPath(endpointUri), [HttpMethods.Get, HttpMethods.Post], confirm)
            .RequireIssuerHost(endpointUri)
            .ExemptFromHostAuthorization();
    }

    internal async Task<IResult> HandleAsync(HttpContext context, IdTokenHintValidator hints, ValidatedClientResolver clients)
    {
        context.Response.Headers.CacheControl = "no-store";

        var parameters = await ReadParametersAsync(context).ConfigureAwait(false);
        var (hint, hintRejected, client) = await ResolveClientAsync(parameters, hints, clients, context.RequestAborted).ConfigureAwait(false);
        var redirect = hintRejected ? null : RedirectFor(client, parameters);

        var sessions = await _session.ReadAsync(context).ConfigureAwait(false);
        if (sessions.IsEmpty)
            return await responses.EndAllAsync(context, sessions, redirect).ConfigureAwait(false);

        // The hinted user, or the client's own account; a hint for a user not signed in here ends nothing.
        var account = hint is not null ? sessions.Find(hint.Subject) : sessions.DefaultFor(client?.ClientId);
        if (account is null)
            return responses.Signed(redirect);

        if (MayEndWithoutAsking(client, hint))
            return await responses.EndAccountAsync(context, sessions, account, redirect).ConfigureAwait(false);

        return await AskAsync(context, new PendingSignOut(client?.ClientId, redirect, account.SessionId, account.Subject))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// The validated hint, whether one was sent that failed to validate, and the client the
    /// sign-out is for: the hint's own when it validated, the one <c>client_id</c> names otherwise.
    /// <c>client_id</c> is passed to the validator as sent, so a hint issued to any other client is
    /// refused.
    /// </summary>
    private async ValueTask<(IdTokenHint? Hint, bool HintRejected, IClient? Client)> ResolveClientAsync(
        Dictionary<string, StringValues> parameters,
        IdTokenHintValidator hints,
        ValidatedClientResolver clients,
        CancellationToken cancellationToken)
    {
        var requestedClientId = Single(parameters, "client_id");
        var idTokenHint = Single(parameters, "id_token_hint");

        var hint = hints.Validate(idTokenHint, requestedClientId);
        var hintRejected = hint is null && idTokenHint is not null;
        if (hintRejected)
            logger.LogDebug("An id_token_hint that is not an ID token this server issued was ignored, and with it any post-logout redirect.");

        var clientId = hint?.ClientId ?? requestedClientId;
        var client = clientId is null
            ? null
            : await clients.FindClientAsync(clientId, cancellationToken).ConfigureAwait(false);

        return (hint, hintRejected, client);
    }

    /// <summary>
    /// The redirect back to the client, when the request asked for one the client registered and
    /// its <c>state</c> is short enough to echo.
    /// </summary>
    private static PostLogoutRedirect? RedirectFor(IClient? client, Dictionary<string, StringValues> parameters)
    {
        var state = Single(parameters, "state");
        if (state is not null && state.Length > MaxStateLength)
            return null;

        return PostLogoutRedirect.For(client, Single(parameters, "post_logout_redirect_uri"), state);
    }

    /// <summary>
    /// Keeps the sign-out for the user to confirm and sends them to the page that asks: the
    /// host's, or the framework's own.
    /// </summary>
    private async Task<IResult> AskAsync(HttpContext context, PendingSignOut pending)
    {
        LogoutRequestContext request;
        try
        {
            request = await requests.CreateAsync(context, pending, context.RequestAborted).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            // Fail closed: a user who could not be asked is not signed out.
            logger.LogError(ex, "Storing a sign-out request for the user to confirm failed.");
            return EndSessionResponses.Unavailable();
        }

        var confirmation = options.Value.EndSessionEndpoint.LogoutPath ?? ConfirmPath(PublishedUri());
        return Results.Redirect(InteractionHandoff.BuildRedirectUrl(confirmation, request.Id));
    }

    /// <summary>
    /// The framework's own confirmation page: the <c>GET</c> renders it, and the form's
    /// <c>POST</c> does exactly what a host page's call to <see cref="LogoutInteraction.SignOutAsync"/> does.
    /// </summary>
    internal async Task<IResult> ConfirmAsync(HttpContext context, LogoutInteraction logout)
    {
        context.Response.Headers.CacheControl = "no-store";

        try
        {
            if (HttpMethods.IsPost(context.Request.Method))
            {
                if (await AsksForEveryAccountAsync(context).ConfigureAwait(false))
                    await logout.SignOutAllAsync().ConfigureAwait(false);
                else
                    await logout.SignOutAsync().ConfigureAwait(false);

                return Results.Empty;
            }

            var request = await logout.TryGetRequestAsync(context.RequestAborted).ConfigureAwait(false);
            return request is null
                ? EndSessionResponses.NothingToConfirm()
                : EndSessionResponses.Confirmation(request.Client, request.SignedInAccounts.Count);
        }
        catch (ZeeKayDaStoreException ex)
        {
            logger.LogError(ex, "Reading a sign-out request the user was asked to confirm failed.");
            return EndSessionResponses.Unavailable();
        }
    }

    /// <summary>
    /// A valid hint, which named the account to end, from a client that opted out of the question.
    /// The hint's client is the one resolved, so the opt-out is that client's own.
    /// </summary>
    private static bool MayEndWithoutAsking(IClient? client, IdTokenHint? hint) =>
        hint is not null && client is { SkipLogoutConfirmation: true };

    /// <summary>Whether the framework's confirmation form was posted with its "every account" button.</summary>
    private static async ValueTask<bool> AsksForEveryAccountAsync(HttpContext context) =>
        context.Request.HasFormContentType
        && (await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false))[EndSessionResponses.ScopeField] == EndSessionResponses.EveryAccount;

    private static async ValueTask<Dictionary<string, StringValues>> ReadParametersAsync(HttpContext context)
    {
        var request = context.Request;

        IEnumerable<KeyValuePair<string, StringValues>> source;
        if (HttpMethods.IsGet(request.Method))
            source = request.Query;
        else if (request.HasFormContentType)
            source = await request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        else
            source = [];

        return new Dictionary<string, StringValues>(source, StringComparer.Ordinal);
    }

    /// <summary>
    /// A parameter's one non-empty value. A parameter sent twice is ignored rather than resolved:
    /// picking one of two values is a decision a request's author gets to influence.
    /// </summary>
    private static string? Single(Dictionary<string, StringValues> parameters, string name) =>
        parameters.TryGetValue(name, out var values) && values.Count == 1 && !string.IsNullOrEmpty(values[0])
            ? values[0]
            : null;

    private Uri PublishedUri() => EndpointRouteHelper.GetPublishedEndpointUri(
        EndpointRouteHelper.GetIssuerUri(options),
        options.Value.EndSessionEndpoint.Uri,
        DefaultPath);

    private static string ConfirmPath(Uri endpointUri) => endpointUri.AbsolutePath.TrimEnd('/') + ConfirmSuffix;
}
