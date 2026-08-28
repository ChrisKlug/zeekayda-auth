using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The authorization endpoint (<c>/connect/authorize</c>, GET and POST per OIDC Core 1.0
/// §3.1.2.1). Currently implements request validation and the two-phase error model (#83);
/// a fully valid request still answers <c>501</c> until the interaction stages land.
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

    public AuthorizationEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
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

    private async Task<IResult> Handle(
        AuthorizeRequestValidator validator,
        HttpContext context)
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
            AuthorizeRequestValidationResult.Valid =>
                // Validation passed; interaction, consent and code issuance land in #85–#87.
                PreAlphaNotImplementedResult.Result,

            AuthorizeRequestValidationResult.RedirectError redirect => RedirectToClient(redirect),

            AuthorizeRequestValidationResult.LocalError local =>
                RenderLocalError(context, local.Error, local.Description),

            _ => throw new InvalidOperationException("Unknown validation result type."),
        };
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

    private IResult RenderLocalError(
        HttpContext context,
        string error,
        string description)
    {
        var errorPath = _options.Value.AuthorizationEndpoint.Interaction.ErrorPath;
        if (errorPath is not null)
        {
            // Resolved lazily so hosts without a configured ErrorPath never need the transport's
            // Data Protection dependency on this path.
            var errorTransport = context.RequestServices.GetRequiredService<AuthorizeErrorTransport>();
            var id = errorTransport.CreateAndAttach(context, error, description);
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
