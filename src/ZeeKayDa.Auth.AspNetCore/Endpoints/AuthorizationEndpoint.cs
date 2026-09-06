using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The authorization endpoint (<c>/connect/authorize</c>, GET and POST per OIDC Core 1.0
/// §3.1.2.1). Validates the request, applies the two-phase error model, stores the interaction
/// context and hands off to authentication and consent; a request past both is answered with an
/// authorization code at the client's registered redirect URI.
/// </summary>
/// <remarks>
/// Phase-1 failures render locally — a minimal framework-written 400 by default, or a redirect
/// to the host's configured <c>Interaction.ErrorPath</c> carrying only an opaque identifier.
/// Phase-2 failures redirect to the validated client with <c>error</c>, <c>state</c> when
/// present, and <c>iss</c> unconditionally (RFC 9207).
/// </remarks>
internal sealed class AuthorizationEndpoint : IZeeKayDaEndpoint
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly AuthorizationFlow _flow;
    private readonly InteractionOutcomes _outcomes;
    private readonly ProviderRegistry _providers;
    private readonly ISanitizingLogger<AuthorizationEndpoint> _logger;

    public AuthorizationEndpoint(
        IOptions<AuthorizationServerOptions> options,
        AuthorizationFlow flow,
        InteractionOutcomes outcomes,
        ProviderRegistry providers,
        ISanitizingLogger<AuthorizationEndpoint> logger)
    {
        _options = options;
        _flow = flow;
        _outcomes = outcomes;
        _providers = providers;
        _logger = logger;
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            _options.Value.AuthorizationEndpoint.Uri,
            "connect/authorize");

        endpoints.MapMethods(
                endpointUri.AbsolutePath,
                [HttpMethods.Get, HttpMethods.Post],
                Handle)
            .RequireIssuerHost(endpointUri);
    }

    private async Task<IResult> Handle(AuthorizeRequestValidator validator, HttpContext context)
    {
        // Authorization responses carry codes and errors that must never be cached or logged
        // from an intermediary cache (RFC 6749 §10.12 guidance, RFC 9700 §4.16).
        context.Response.Headers.CacheControl = "no-store";

        var parameters = await ExtractParametersAsync(context).ConfigureAwait(false);
        if (parameters is null)
            return RenderLocalError(
                context,
                AuthorizeRequestErrors.InvalidRequest,
                "A POST authorization request must use application/x-www-form-urlencoded serialization.");

        var result = await validator.ValidateAsync(parameters, context.RequestAborted).ConfigureAwait(false);

        // A request that fails validation never wrote an interaction, and touches none that
        // another tab has in flight.
        return result switch
        {
            AuthorizeRequestValidationResult.Valid valid =>
                await BeginInteractionAsync(context, valid.Request).ConfigureAwait(false),

            AuthorizeRequestValidationResult.RedirectError redirect => RedirectToClient(redirect),

            AuthorizeRequestValidationResult.LocalError local => RenderLocalError(context, local.Error, local.Description),

            _ => throw new InvalidOperationException("Unknown validation result type."),
        };
    }

    /// <summary>
    /// Stores the interaction context the rest of the flow reads, then hands off: to the host's
    /// login page when the request must be authenticated, or straight on when an SSO session
    /// already answers for the user.
    /// </summary>
    private async Task<IResult> BeginInteractionAsync(HttpContext context, ValidatedAuthorizeRequest request)
    {
        var session = await _flow.ReadSessionAsync(context).ConfigureAwait(false);
        var needsAuthentication = _flow.NeedsAuthentication(request, session);

        // A continuing request carries the session it continues on; a request about to be
        // authenticated carries no subject, because it has none yet.
        var requestContext = _flow.CreateContext(request, needsAuthentication ? null : session);

        try
        {
            await _flow.PersistAsync(context, requestContext).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            // The redirect target is authenticated by now, so the client learns the server failed
            // and the operator learns which store operation did.
            _logger.LogError(ex, "Storing the authorization request for client {ClientId} failed.", request.Client.ClientId);

            return RedirectToClient(request, AuthorizeRequestErrors.ServerError, InteractionOutcomes.CouldNotStoreRequest);
        }

        if (!needsAuthentication)
            return await _outcomes.ContinueAsync(context, requestContext).ConfigureAwait(false);

        if (request.Prompts.Contains(PromptValue.None))
        {
            // prompt=none is a promise not to show the user anything. The only honest answer to
            // "authenticate without interacting" is that authentication is required.
            return await FailRequestAsync(context, requestContext, () => RedirectToClient(
                request,
                AuthorizeRequestErrors.LoginRequired,
                "The request specified prompt=none but no authenticated session is available.")).ConfigureAwait(false);
        }

        var interaction = _options.Value.AuthorizationEndpoint.Interaction;
        switch (LoginDispatch.Decide(interaction, _providers.Count))
        {
            case LoginDispatchRule.LoginPage when interaction.LoginPath is { } loginPath:
                return Results.Redirect(InteractionHandoff.BuildRedirectUrl(loginPath, requestContext.Id));

            case LoginDispatchRule.SingleProvider:
                // The framework can choose, so the user never sees a page of the host's: the
                // handler writes the redirect to the provider itself.
                await _outcomes.ChallengeAsync(context, requestContext, _providers.Registrations[0]).ConfigureAwait(false);
                return Results.Empty;

            default:
                // A configuration failure, reported to the client rather than rendered at the
                // user: the redirect target is authenticated by this point, and the client's own
                // error page is where a developer will be looking. Startup warned about this too.
                return await FailRequestAsync(context, requestContext, () => RedirectToClient(
                    request,
                    AuthorizeRequestErrors.ServerError,
                    "The authorization server is not configured to authenticate users.")).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Discards the interaction just written before answering an error: a request that ends here
    /// must not leave its interaction alive for a later sign-in to pick up.
    /// </summary>
    private async Task<IResult> FailRequestAsync(HttpContext context, AuthorizationRequestContext requestContext, Func<IResult> respond)
    {
        await _flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        return respond();
    }

    /// <summary>
    /// Extracts the parameter multi-map from the request's OIDC serialization — the query string
    /// for GET, the form body for POST. Returns <see langword="null"/> for a POST without a form
    /// content type.
    /// </summary>
    private static async ValueTask<IReadOnlyDictionary<string, IReadOnlyList<string?>>?> ExtractParametersAsync(
        HttpContext context)
    {
        IEnumerable<KeyValuePair<string, StringValues>> source;
        if (HttpMethods.IsGet(context.Request.Method))
        {
            source = context.Request.Query;
        }
        else
        {
            if (!context.Request.HasFormContentType)
                return null;

            source = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        }

        var parameters = new Dictionary<string, IReadOnlyList<string?>>(StringComparer.Ordinal);
        foreach (var (key, values) in source)
            parameters[key] = values.ToArray();

        return parameters;
    }

    /// <summary>
    /// Delivers an error raised after validation passed — the interaction stage's own refusals —
    /// to the redirect URI phase 1 authenticated.
    /// </summary>
    private IResult RedirectToClient(ValidatedAuthorizeRequest request, string error, string description) =>
        _outcomes.ClientError(request.RedirectUri, error, description, request.State);

    private IResult RedirectToClient(AuthorizeRequestValidationResult.RedirectError error) =>
        _outcomes.ClientError(error.RedirectUri, error.Error, error.Description, error.State);

    private IResult RenderLocalError(HttpContext context, string error, string description) =>
        _outcomes.LocalError(context, error, description);
}
