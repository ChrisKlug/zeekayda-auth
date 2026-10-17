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
    private readonly SanitizingLogger<AuthorizationEndpoint> _logger;

    public AuthorizationEndpoint(
        IOptions<AuthorizationServerOptions> options,
        AuthorizationFlow flow,
        InteractionOutcomes outcomes,
        ProviderRegistry providers,
        SanitizingLogger<AuthorizationEndpoint> logger)
    {
        _options = options;
        _flow = flow;
        _outcomes = outcomes;
        _providers = providers;
        _logger = logger;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Not served when <c>GrantTypesSupported</c> lacks the authorization code grant, which is how a
    /// host declares it has no interactive flow; discovery omits the endpoint on the same condition.
    /// </remarks>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        if (!_options.Value.GrantTypesSupported.Contains(GrantType.AuthorizationCode))
            return;

        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            _options.Value.AuthorizationEndpoint.Uri,
            "connect/authorize");

        endpoints.MapMethods(
                endpointUri.AbsolutePath,
                [HttpMethods.Get, HttpMethods.Post],
                Handle)
            .RequireIssuerHost(endpointUri)
            .ExemptFromHostAuthorization();
    }

    internal async Task<IResult> Handle(AuthorizeRequestValidator validator, HttpContext context)
    {
        // Codes and errors must never be cached (RFC 9700 §4.3).
        context.Response.Headers.CacheControl = "no-store";

        var parameters = await ExtractParametersAsync(context).ConfigureAwait(false);
        if (parameters is null)
            return RenderLocalError(
                context,
                AuthorizeRequestErrors.InvalidRequest,
                "A POST authorization request must use application/x-www-form-urlencoded serialization.");

        var result = await validator.ValidateAsync(parameters, context.RequestAborted).ConfigureAwait(false);

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
        // There is no account picker, and a server that cannot obtain a selection must say so
        // (OIDC Core §3.1.2.1) rather than continue as whichever account holds the session.
        if (request.Prompts.Contains(PromptValue.SelectAccount))
        {
            return RedirectToClient(
                request,
                AuthorizeRequestErrors.AccountSelectionRequired,
                "The request specified prompt=select_account, but this server cannot prompt the user to select an account.");
        }

        var session = await _flow.ReadSessionAsync(context).ConfigureAwait(false);
        var needsAuthentication = _flow.NeedsAuthentication(request, session);

        var loginRequired = needsAuthentication && request.Prompts.Contains(PromptValue.None);
        if (loginRequired)
        {
            // OIDC Core §3.1.2.6. Answered before anything is stored: nothing would ever read it.
            return RedirectToClient(
                request,
                AuthorizeRequestErrors.LoginRequired,
                "The request specified prompt=none but no authenticated session is available.");
        }

        var continuedSession = needsAuthentication ? null : session;
        var requestContext = _flow.CreateContext(request, continuedSession);

        try
        {
            if (!await _flow.TryPersistAsync(context, requestContext).ConfigureAwait(false))
            {
                // Rendered, not redirected: echoing an oversized `state` byte for byte (RFC 6749 §4.1.2.1)
                // makes a Location that the client's server may or may not accept.
                return RenderLocalError(context, AuthorizeRequestErrors.InvalidRequest, InteractionOutcomes.TooLarge);
            }
        }
        catch (ZeeKayDaStoreException ex)
        {
            _logger.LogError(ex, "Storing the authorization request for client {ClientId} failed.", request.Client.ClientId);

            return RedirectToClient(request, AuthorizeRequestErrors.ServerError, InteractionOutcomes.CouldNotStoreRequest);
        }

        if (!needsAuthentication)
            return await _outcomes.ContinueAsync(context, requestContext).ConfigureAwait(false);

        var interaction = _options.Value.AuthorizationEndpoint.Interaction;
        switch (LoginDispatch.Decide(interaction, _providers.Count))
        {
            case LoginDispatchRule.LoginPage when interaction.LoginPath is { } loginPath:
                return Results.Redirect(InteractionHandoff.BuildRedirectUrl(loginPath, requestContext.Id));

            case LoginDispatchRule.SingleProvider:
                // The only provider: no host page is needed to choose one.
                await _outcomes.ChallengeAsync(context, requestContext, _providers.Registrations[0]).ConfigureAwait(false);
                return Results.Empty;

            default:
                // No login page and no single provider. Startup warned; the client's developer sees this.
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
