using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The three ways an authorization request is answered: locally, when nothing may be sent to the
/// client; at the client's registered redirect URI with an error; or at that URI with an
/// authorization code.
/// </summary>
/// <remarks>
/// <para>
/// A local answer is for an error that must not be redirected — either because the redirect
/// target was never authenticated (a phase-1 failure), or because building the redirect is itself
/// the thing that failed: a redirect to the host's configured <c>Interaction.ErrorPath</c>
/// carrying only an opaque identifier, or a minimal framework-written 400 when no error page is
/// configured. Details never travel in the query string, where they would reach proxy logs and
/// browser history.
/// </para>
/// <para>
/// An answer at the client always goes to a redirect URI that came from validated state — a
/// matched registration, or the decrypted interaction context — and never from request input.
/// That is what keeps this from being an unauthenticated redirect primitive. Every such answer
/// carries <c>iss</c>, unconditionally, as mix-up attack mitigation (RFC 9207, RFC 9700 §4.4).
/// </para>
/// </remarks>
internal sealed class AuthorizationResponses
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly AuthorizeErrorTransport _errorTransport;

    public AuthorizationResponses(IOptions<AuthorizationServerOptions> options, AuthorizeErrorTransport errorTransport)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(errorTransport);

        _options = options;
        _errorTransport = errorTransport;
    }

    /// <summary>An error rendered at the user, never redirected to the client.</summary>
    public IResult Local(HttpContext context, string error, string description)
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

    /// <summary>
    /// The redirect carrying <paramref name="error"/> and <paramref name="description"/> to
    /// <paramref name="redirectUri"/>, echoing <paramref name="state"/> when the client sent one.
    /// </summary>
    public IResult ErrorAtClient(string redirectUri, string error, string description, string? state)
    {
        ArgumentException.ThrowIfNullOrEmpty(redirectUri);
        ArgumentException.ThrowIfNullOrEmpty(error);
        ArgumentException.ThrowIfNullOrEmpty(description);

        return AtClient(redirectUri, state, new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["error"] = error,
            ["error_description"] = description,
        });
    }

    /// <summary>
    /// The successful authorization response: the redirect carrying <paramref name="code"/> to
    /// <paramref name="redirectUri"/>, echoing <paramref name="state"/> when the client sent one.
    /// </summary>
    public IResult CodeAtClient(string redirectUri, string code, string? state)
    {
        ArgumentException.ThrowIfNullOrEmpty(redirectUri);
        ArgumentException.ThrowIfNullOrEmpty(code);

        return AtClient(redirectUri, state, new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["code"] = code,
        });
    }

    private IResult AtClient(string redirectUri, string? state, Dictionary<string, string?> query)
    {
        if (state is not null)
            query["state"] = state;

        query["iss"] = _options.Value.Issuer!;

        return new UnloggedRedirect(QueryHelpers.AddQueryString(redirectUri, query));
    }

    /// <summary>
    /// A redirect written without going through <see cref="Results.Redirect(string, bool, bool)"/>,
    /// whose executor logs the full <c>Location</c> at <c>Information</c>. A response to the
    /// client carries the authorization code and the client's <c>state</c>, neither of which may
    /// reach a log sink, so the framework writes the two headers itself.
    /// </summary>
    private sealed class UnloggedRedirect(string location) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            ArgumentNullException.ThrowIfNull(httpContext);

            httpContext.Response.StatusCode = StatusCodes.Status302Found;
            httpContext.Response.Headers.Location = location;

            return Task.CompletedTask;
        }
    }
}
