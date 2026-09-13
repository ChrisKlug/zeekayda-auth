using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// The token endpoint's wire responses (RFC 6749 §5): the success body, the error body, and
/// the status codes and headers each carries.
/// </summary>
internal static class TokenResponses
{
    /// <summary>
    /// Every token response carries a credential or says why one was refused; neither may be
    /// cached (RFC 6749 §5.1, which asks for both headers; OAuth 2.1 keeps the first).
    /// </summary>
    public static void MarkUncacheable(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
    }

    public static IResult Tokens(TokenResponse body) =>
        Results.Json(body, ZeeKayDaJsonSerializerContext.Default.TokenResponse, statusCode: StatusCodes.Status200OK);

    public static IResult Error(TokenError error) => Error(error, StatusCodes.Status400BadRequest);

    public static IResult ServerError() =>
        Error(new TokenError(TokenRequestErrors.ServerError, "The authorization server could not complete the request."),
            StatusCodes.Status500InternalServerError);

    /// <summary>
    /// Client authentication failed. A client that used one <c>Authorization</c> header is
    /// answered <c>401</c> with a <c>WWW-Authenticate</c> naming the scheme it used (RFC 6749 §5.2
    /// MUST); one that sent none, or two, is answered <c>400</c>. The description never says
    /// which of "unknown client" and "wrong credential" it was.
    /// </summary>
    public static IResult InvalidClient(HttpContext context)
    {
        var error = new TokenError(TokenRequestErrors.InvalidClient, "Client authentication failed.");

        if (PresentedScheme(context.Request.Headers) is not { } scheme)
            return Error(error, StatusCodes.Status400BadRequest);

        context.Response.Headers.WWWAuthenticate = $"{scheme} realm=\"token\"";
        return Error(error, StatusCodes.Status401Unauthorized);
    }

    private static string? PresentedScheme(IHeaderDictionary headers)
    {
        var authorization = headers.Authorization;

        if (authorization.Count != 1 || !AuthenticationHeaderValue.TryParse(authorization[0], out var header))
            return null;

        return header.Scheme;
    }

    private static IResult Error(TokenError error, int statusCode) =>
        Results.Json(
            new TokenErrorResponse(error.Error, error.Description),
            ZeeKayDaJsonSerializerContext.Default.TokenErrorResponse,
            statusCode: statusCode);
}

/// <summary>The successful token response body (RFC 6749 §5.1, OIDC Core §3.1.3.3).</summary>
internal sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] long ExpiresIn,
    [property: JsonPropertyName("id_token")] string IdToken,
    [property: JsonPropertyName("scope")] string Scope);

/// <summary>The error response body (RFC 6749 §5.2).</summary>
internal sealed record TokenErrorResponse(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);
