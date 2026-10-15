using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The ways an authorization request is answered: locally, or at a redirect URI from validated
/// state with an error or a code, always carrying <c>iss</c> (RFC 9207, RFC 9700 §4.4).
/// </summary>
/// <remarks>
/// A local error goes to <c>Interaction.ErrorPath</c> with only an opaque identifier, since a query
/// string reaches logs and history, or is a minimal 400 when no page is configured.
/// </remarks>
internal sealed class AuthorizationResponses(
    IOptions<AuthorizationServerOptions> options,
    AuthorizeErrorTransport errorTransport)
{
    /// <summary>A rejected request's error, rendered at the user, never redirected to the client.</summary>
    public IResult Local(HttpContext context, string error, string description) =>
        Local(context, AuthorizationErrorKind.RequestRejected, error, description);

    /// <summary>An error of <paramref name="kind"/>, rendered at the user, never redirected to the client.</summary>
    public IResult Local(HttpContext context, AuthorizationErrorKind kind, string error, string description)
    {
        ArgumentNullException.ThrowIfNull(context);

        var errorPath = options.Value.AuthorizationEndpoint.Interaction.ErrorPath;
        if (errorPath is not null)
        {
            var id = errorTransport.CreateAndAttach(context, kind, error, description);
            return Results.Redirect(QueryHelpers.AddQueryString(
                errorPath, AuthorizeErrorTransport.QueryParameterName, id));
        }

        // The framework's own text, encoded anyway so a future description cannot inject.
        var (heading, advice) = kind == AuthorizationErrorKind.NothingToContinue
            ? ("There is nothing to continue.", "Return to the application and start again.")
            : ("This sign-in request is invalid.", "Contact the application you arrived from; the request it sent cannot be completed.");

        var html =
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
            "<title>Sign-in request error</title></head><body>" +
            $"<h1>{heading}</h1>" +
            $"<p>{HtmlEncoder.Default.Encode(description)}</p>" +
            $"<p><code>{HtmlEncoder.Default.Encode(error)}</code></p>" +
            $"<p>{advice}</p>" +
            "</body></html>";

        return RenderedPage.Html(StatusCodes.Status400BadRequest, html);
    }

    /// <summary>The redirect carrying <paramref name="error"/> to <paramref name="redirectUri"/>.</summary>
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

    /// <summary>The <c>access_denied</c> redirect for <paramref name="denial"/>, with its <c>zkd_error</c> when <paramref name="withSubCode"/>.</summary>
    public IResult DeniedAtClient(string redirectUri, Denial denial, bool withSubCode, string? state)
    {
        ArgumentException.ThrowIfNullOrEmpty(redirectUri);
        ArgumentNullException.ThrowIfNull(denial);

        var query = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["error"] = AuthorizeRequestErrors.AccessDenied,
            ["error_description"] = denial.Description,
        };

        if (withSubCode)
            query[Denial.ZkdErrorParameter] = denial.ZkdError;

        return AtClient(redirectUri, state, query);
    }

    /// <summary>The successful authorization response, carrying <paramref name="code"/>.</summary>
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

        query["iss"] = options.Value.Issuer!;

        return new UnloggedRedirect(QueryHelpers.AddQueryString(redirectUri, query));
    }
}
