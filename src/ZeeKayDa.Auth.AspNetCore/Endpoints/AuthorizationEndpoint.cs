using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The authorization endpoint (<c>/connect/authorize</c>, GET and POST per OIDC Core 1.0
/// §3.1.2.1). Currently implements request validation, the two-phase error model, and writing
/// the interaction context; a fully valid request still answers <c>501</c> until the handoff,
/// consent and code-issuance stages land.
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
    private readonly AuthorizationRequestContextTransport _contextTransport;
    private readonly AuthorizeErrorTransport _errorTransport;
    private readonly TimeProvider _timeProvider;

    public AuthorizationEndpoint(
        IOptions<AuthorizationServerOptions> options,
        AuthorizationRequestContextTransport contextTransport,
        AuthorizeErrorTransport errorTransport,
        TimeProvider timeProvider)
    {
        _options = options;
        _contextTransport = contextTransport;
        _errorTransport = errorTransport;
        _timeProvider = timeProvider;
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
                BeginInteraction(context, valid.Request),

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
        _contextTransport.Delete(context);
        return respond();
    }

    /// <summary>
    /// Writes the interaction context that the rest of the flow reads, then hands off. Handoff,
    /// consent and code issuance are not built yet, so a request that gets this far still answers
    /// <c>501</c> — but it answers it having persisted the state those stages will need.
    /// </summary>
    private IResult BeginInteraction(HttpContext context, ValidatedAuthorizeRequest request)
    {
        var now = _timeProvider.GetUtcNow();
        var requestContext = new AuthorizationRequestContext
        {
            Id = StoreKeyGenerator.Generate(),
            ClientId = request.Client.ClientId,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scopes,
            State = request.State,
            Nonce = request.Nonce,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            Prompts = request.Prompts,
            MaxAge = request.MaxAge,
            IssuedAt = now,
            ExpiresAt = now + AuthorizationRequestContextTransport.Lifetime,
        };

        if (!_contextTransport.TryWrite(context, requestContext))
        {
            // The one phase-2 failure that renders locally rather than redirecting. `state` must
            // round-trip byte for byte (RFC 6749 §4.1.2.1), so echoing an oversized one produces a
            // Location the browser cannot follow and the client never receives — a redirect that
            // fails silently is worse than an error page that does not.
            return RenderLocalError(
                context,
                AuthorizeRequestErrors.InvalidRequest,
                "The authorization request is too large to process.");
        }

        return PreAlphaNotImplementedResult.Result;
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

    private IResult RedirectToClient(AuthorizeRequestValidationResult.RedirectError error)
    {
        var query = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["error"] = error.Error,
            ["error_description"] = error.Description,
        };

        if (error.State is not null)
            query["state"] = error.State;

        // iss on every authorization response, unconditionally — mix-up attack mitigation
        // (RFC 9207, RFC 9700 §4.4).
        query["iss"] = _options.Value.Issuer!;

        return Results.Redirect(QueryHelpers.AddQueryString(error.RedirectUri, query));
    }

    private IResult RenderLocalError(HttpContext context, string error, string description)
    {
        var errorPath = _options.Value.AuthorizationEndpoint.Interaction.ErrorPath;
        if (errorPath is not null)
        {
            var id = _errorTransport.CreateAndAttach(context, error, description);
            return Results.Redirect(QueryHelpers.AddQueryString(
                errorPath, AuthorizeErrorTransport.QueryParameterName, id));
        }

        // Unbranded fallback for hosts that have not configured an error page. The values are
        // the framework's own constants — no request value is ever echoed — but they are
        // HTML-encoded anyway so a future description can never become an injection vector.
        var html =
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
            "<title>Sign-in request error</title></head><body>" +
            "<h1>This sign-in request is invalid.</h1>" +
            $"<p>{HtmlEncoder.Default.Encode(description)}</p>" +
            $"<p><code>{HtmlEncoder.Default.Encode(error)}</code></p>" +
            "<p>Contact the application you arrived from; the request it sent cannot be completed.</p>" +
            "</body></html>";

        return Results.Content(html, "text/html; charset=utf-8", statusCode: StatusCodes.Status400BadRequest);
    }
}
