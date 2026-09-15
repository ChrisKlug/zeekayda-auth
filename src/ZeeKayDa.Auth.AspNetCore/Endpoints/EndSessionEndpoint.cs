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
/// Nothing a sign-out sends is refused. A parameter that fails to validate is ignored, as §4
/// requires of an <c>id_token_hint</c>, and the worst a bad request can do is land the user on a
/// confirmation or signed-out page instead of back at the client.
/// </para>
/// <para>
/// The user is signed out without being asked only when there is no session to end, or when a
/// valid <c>id_token_hint</c> names the user of the current session and its client opted out of
/// the question with <c>SkipLogoutConfirmation</c>. Everything else is confirmed first (§2).
/// </para>
/// </remarks>
internal sealed class EndSessionEndpoint : IZeeKayDaEndpoint
{
    /// <summary>
    /// The longest <c>state</c> echoed to a client — far above what a relying party sends. A
    /// sign-out carrying a longer one is not sent back to the client at all, rather than sent back
    /// with a <c>state</c> the client cannot match.
    /// </summary>
    internal const int MaxStateLength = 2048;

    private const string DefaultPath = "connect/endsession";
    private const string ConfirmSuffix = "/confirm";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly SsoSession _session;
    private readonly LogoutRequestStore _requests;
    private readonly EndSessionResponses _responses;
    private readonly ISanitizingLogger<EndSessionEndpoint> _logger;

    public EndSessionEndpoint(
        IOptions<AuthorizationServerOptions> options,
        SsoSession session,
        LogoutRequestStore requests,
        EndSessionResponses responses,
        ISanitizingLogger<EndSessionEndpoint> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(requests);
        ArgumentNullException.ThrowIfNull(responses);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _session = session;
        _requests = requests;
        _responses = responses;
        _logger = logger;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Served on the same condition as the authorization endpoint: only the authorization code
    /// flow signs anyone in, so a host without it has no session to end.
    /// </remarks>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        if (!_options.Value.GrantTypesSupported.Contains(GrantType.AuthorizationCode))
            return;

        var endpointUri = PublishedUri();

        // AllowAnonymous so a host-wide authorization fallback policy cannot challenge a sign-out
        // with the host's scheme: the SSO session is not the host's scheme.
        Delegate handler = HandleAsync;
        endpoints.MapMethods(endpointUri.AbsolutePath, [HttpMethods.Get, HttpMethods.Post], handler)
            .RequireIssuerHost(endpointUri)
            .AllowAnonymous();

        if (_options.Value.EndSessionEndpoint.LogoutPath is not null)
            return;

        Delegate confirm = ConfirmAsync;
        endpoints.MapMethods(ConfirmPath(endpointUri), [HttpMethods.Get, HttpMethods.Post], confirm)
            .RequireIssuerHost(endpointUri)
            .AllowAnonymous();
    }

    private async Task<IResult> HandleAsync(HttpContext context, IdTokenHintValidator hints, ValidatedClientResolver clients)
    {
        context.Response.Headers.CacheControl = "no-store";

        var parameters = await ReadParametersAsync(context).ConfigureAwait(false);
        var requestedClientId = Single(parameters, "client_id");
        var idTokenHint = Single(parameters, "id_token_hint");

        var hint = hints.Validate(idTokenHint, requestedClientId);
        if (hint is null && idTokenHint is not null)
            _logger.LogDebug("An id_token_hint that is not an ID token this server issued was ignored.");

        var clientId = hint?.ClientId ?? requestedClientId;
        var client = clientId is null
            ? null
            : await clients.FindByClientIdAsync(clientId, context.RequestAborted).ConfigureAwait(false);

        var state = Single(parameters, "state");
        var redirectUri = client is not null
            && Single(parameters, "post_logout_redirect_uri") is { } requested
            && EndSessionResponses.IsRegistered(client, requested)
            && (state is null || state.Length <= MaxStateLength)
            ? requested
            : null;
        var echoedState = redirectUri is null ? null : state;

        var session = await _session.ReadAsync(context).ConfigureAwait(false);
        if (session is null || MayEndWithoutAsking(client, hint, session))
            return await _responses.SignOutAsync(context, redirectUri, echoedState).ConfigureAwait(false);

        LogoutRequestContext request;
        try
        {
            request = await _requests.CreateAsync(context, client?.ClientId, redirectUri, echoedState, context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            // Fail closed: a user who could not be asked is not signed out.
            _logger.LogError(ex, "Storing a sign-out request for the user to confirm failed.");
            return EndSessionResponses.Unavailable();
        }

        var confirmation = _options.Value.EndSessionEndpoint.LogoutPath ?? ConfirmPath(PublishedUri());
        return Results.Redirect(InteractionHandoff.BuildRedirectUrl(confirmation, request.Id));
    }

    /// <summary>
    /// The framework's own confirmation page: the <c>GET</c> renders it, and the form's
    /// <c>POST</c> does exactly what a host page's call to <see cref="ILogoutInteraction.SignOutAsync"/> does.
    /// </summary>
    private async Task<IResult> ConfirmAsync(HttpContext context, ILogoutInteraction logout)
    {
        context.Response.Headers.CacheControl = "no-store";

        try
        {
            if (HttpMethods.IsPost(context.Request.Method))
            {
                await logout.SignOutAsync().ConfigureAwait(false);
                return Results.Empty;
            }

            var request = await logout.GetRequestAsync(context.RequestAborted).ConfigureAwait(false);
            return EndSessionResponses.Confirmation(request.Client);
        }
        catch (ZeeKayDaInteractionException)
        {
            return EndSessionResponses.NothingToConfirm();
        }
        catch (ZeeKayDaStoreException ex)
        {
            _logger.LogError(ex, "Reading a sign-out request the user was asked to confirm failed.");
            return EndSessionResponses.Unavailable();
        }
    }

    /// <summary>
    /// A valid hint for the user signed in to this browser, from a client that opted out of the
    /// question. The hint's client is the one resolved, so the opt-out is that client's own.
    /// </summary>
    private static bool MayEndWithoutAsking(IClientMetadata? client, IdTokenHint? hint, SsoSessionState session) =>
        hint is not null
        && client is { SkipLogoutConfirmation: true }
        && string.Equals(hint.Subject, session.Subject, StringComparison.Ordinal);

    /// <summary>
    /// The request's parameters: the query string for a GET, the form body for a POST. A POST that
    /// is not form-encoded carries nothing this endpoint can read (§2), and is treated as carrying
    /// nothing.
    /// </summary>
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
        EndpointRouteHelper.GetIssuerUri(_options),
        _options.Value.EndSessionEndpoint.Uri,
        DefaultPath);

    private static string ConfirmPath(Uri endpointUri) => endpointUri.AbsolutePath.TrimEnd('/') + ConfirmSuffix;
}
