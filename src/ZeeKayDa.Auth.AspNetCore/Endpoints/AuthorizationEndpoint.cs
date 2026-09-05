using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The authorization endpoint (<c>/connect/authorize</c>, GET and POST per OIDC Core 1.0
/// §3.1.2.1). Validates the request, applies the two-phase error model, writes the interaction
/// context and hands off to authentication and consent; a request past both still answers
/// <c>501</c> until code issuance lands.
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

    public AuthorizationEndpoint(
        IOptions<AuthorizationServerOptions> options,
        AuthorizationFlow flow,
        InteractionOutcomes outcomes,
        ProviderRegistry providers)
    {
        _options = options;
        _flow = flow;
        _outcomes = outcomes;
        _providers = providers;
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

        return result switch
        {
            AuthorizeRequestValidationResult.Valid valid =>
                await BeginInteractionAsync(context, valid.Request).ConfigureAwait(false),

            AuthorizeRequestValidationResult.RedirectError redirect => FailRequest(
                context, () => RedirectToClient(redirect)),

            AuthorizeRequestValidationResult.LocalError local => FailRequest(
                context, () => RenderLocalError(context, local.Error, local.Description)),

            _ => throw new InvalidOperationException("Unknown validation result type."),
        };
    }

    /// <summary>
    /// Clears any interaction context before answering an error. A request that fails validation
    /// must not leave an earlier interaction alive to be picked up by the next sign-in — including
    /// one a cross-site request planted.
    /// </summary>
    private IResult FailRequest(HttpContext context, Func<IResult> respond)
    {
        _flow.Clear(context);
        return respond();
    }

    /// <summary>
    /// Writes the interaction context the rest of the flow reads, then hands off: to the host's
    /// login page when the request must be authenticated, or straight on when an SSO session
    /// already answers for the user.
    /// </summary>
    private async Task<IResult> BeginInteractionAsync(HttpContext context, ValidatedAuthorizeRequest request)
    {
        var session = await _flow.ReadSessionAsync(context).ConfigureAwait(false);
        var needsAuthentication = _flow.NeedsAuthentication(request, session);

        // The context is written before any handoff decision: a request that cannot be carried at
        // all is a fact about the request, and answering it with a decision about the user's
        // session would report the second problem this request has rather than the first.
        // A continuing request carries the session it continues on; a request about to be
        // authenticated carries no subject, because it has none yet.
        var requestContext = _flow.CreateContext(request, needsAuthentication ? null : session);

        if (!_flow.TryPersist(context, requestContext))
        {
            // The one phase-2 failure that renders locally rather than redirecting. `state` must
            // round-trip byte for byte (RFC 6749 §4.1.2.1), so echoing an oversized one builds a
            // Location whose length depends on how the value percent-encodes — sometimes past what
            // the client's server will accept, sometimes not. A deterministic error page beats a
            // redirect that works or fails silently depending on the bytes in `state`. §4.1.2.1
            // describes redirecting phase-2 errors rather than requiring it; the only MUST NOT is
            // redirecting to an invalid URI, which this does not do.
            return FailRequest(
                context,
                () => RenderLocalError(
                    context,
                    AuthorizeRequestErrors.InvalidRequest,
                    "The authorization request is too large to process."));
        }

        if (!needsAuthentication)
            return await _outcomes.ContinueAsync(context, requestContext).ConfigureAwait(false);

        if (request.Prompts.Contains(PromptValue.None))
        {
            // prompt=none is a promise not to show the user anything. The only honest answer to
            // "authenticate without interacting" is that authentication is required.
            return FailRequest(context, () => RedirectToClient(
                request,
                AuthorizeRequestErrors.LoginRequired,
                "The request specified prompt=none but no authenticated session is available."));
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
                return FailRequest(context, () => RedirectToClient(
                    request,
                    AuthorizeRequestErrors.ServerError,
                    "The authorization server is not configured to authenticate users."));
        }
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
    /// through the same phase-2 channel validation failures use.
    /// </summary>
    private IResult RedirectToClient(ValidatedAuthorizeRequest request, string error, string description) =>
        RedirectToClient(new AuthorizeRequestValidationResult.RedirectError
        {
            RedirectUri = request.RedirectUri,
            Error = error,
            Description = description,
            State = request.State,
        });

    private IResult RedirectToClient(AuthorizeRequestValidationResult.RedirectError error) =>
        _outcomes.ClientError(error.RedirectUri, error.Error, error.Description, error.State);

    private IResult RenderLocalError(HttpContext context, string error, string description) =>
        _outcomes.LocalError(context, error, description);
}
