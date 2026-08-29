using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Renders an authorization error that must not be redirected to the client — either because the
/// redirect target was never authenticated (a phase-1 failure), or because building the redirect
/// is itself the thing that failed.
/// </summary>
/// <remarks>
/// A redirect to the host's configured <c>Interaction.ErrorPath</c> carrying only an opaque
/// identifier, or a minimal framework-written 400 when no error page is configured. Details never
/// travel in the query string, where they would reach proxy logs and browser history.
/// </remarks>
internal sealed class LocalErrorResponse
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly AuthorizeErrorTransport _errorTransport;

    public LocalErrorResponse(IOptions<AuthorizationServerOptions> options, AuthorizeErrorTransport errorTransport)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(errorTransport);

        _options = options;
        _errorTransport = errorTransport;
    }

    public IResult Render(HttpContext context, string error, string description)
    {
        ArgumentNullException.ThrowIfNull(context);

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
