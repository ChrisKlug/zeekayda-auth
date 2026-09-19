using System.Buffers;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The userinfo endpoint's wire responses: the claims body, and the RFC 6750 §3 challenges that
/// stand in for an error body at a protected resource.
/// </summary>
/// <remarks>
/// A protected resource reports a refusal in <c>WWW-Authenticate</c>, not in a JSON body — OpenID
/// Connect Core §5.3.3 defers to RFC 6750 §3 for exactly this — so every refusal here carries the
/// header and no body at all.
/// </remarks>
internal static class UserInfoResponses
{
    private const string Realm = "userinfo";

    /// <summary>
    /// The subject's claims. Never cached: they are personal data read with a credential.
    /// </summary>
    /// <remarks>
    /// Written directly rather than serialized: a claim value is already the JSON it must appear
    /// as, and each name is written verbatim, so no naming policy can rewrite a claim name on the
    /// way out.
    /// </remarks>
    public static IResult Claims(HttpContext context, IReadOnlyDictionary<string, ClaimValue> claims)
    {
        context.Response.Headers.CacheControl = "no-store";

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var (name, value) in claims)
            {
                writer.WritePropertyName(name);
                value.WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        return Results.Bytes(buffer.WrittenSpan.ToArray(), "application/json");
    }

    /// <summary>
    /// No credential was presented at all. RFC 6750 §3.1: a bare challenge, naming no error, so a
    /// client that simply forgot the header is not told that some token would have been wrong.
    /// </summary>
    public static IResult MissingToken(HttpContext context) =>
        Challenge(context, StatusCodes.Status401Unauthorized, $"Bearer realm=\"{Realm}\"");

    /// <summary>
    /// The credential was presented but is not one this server will honour. One description for
    /// every cause — unsigned, expired, addressed elsewhere, a client or subject no longer served
    /// — so a caller cannot tell them apart.
    /// </summary>
    public static IResult InvalidToken(HttpContext context) =>
        Challenge(
            context,
            StatusCodes.Status401Unauthorized,
            $"Bearer realm=\"{Realm}\", error=\"invalid_token\", " +
            "error_description=\"The access token is invalid, expired, revoked, was not issued for this server, " +
            "or its subject can no longer be served.\"");

    /// <summary>The token is live but was not granted <c>openid</c> (RFC 6750 §3.1, OpenID Connect Core §5.3.1).</summary>
    public static IResult InsufficientScope(HttpContext context) =>
        Challenge(
            context,
            StatusCodes.Status403Forbidden,
            $"Bearer realm=\"{Realm}\", error=\"insufficient_scope\", scope=\"openid\", " +
            "error_description=\"The access token was not issued with the openid scope.\"");

    /// <summary>The request presented its token in more than one way, or in none this endpoint reads.</summary>
    public static IResult InvalidRequest(HttpContext context, string description) =>
        Challenge(
            context,
            StatusCodes.Status400BadRequest,
            $"Bearer realm=\"{Realm}\", error=\"invalid_request\", error_description=\"{description}\"");

    /// <summary>A fault at this end, already logged. Nothing about it reaches the caller.</summary>
    public static IResult ServerError(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }

    private static IResult Challenge(HttpContext context, int statusCode, string challenge)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.WWWAuthenticate = challenge;
        return Results.StatusCode(statusCode);
    }
}
