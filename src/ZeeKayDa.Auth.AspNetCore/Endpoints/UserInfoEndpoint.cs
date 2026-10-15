using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Tokens;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The UserInfo endpoint (<c>/connect/userinfo</c>, GET and POST per OpenID Connect Core §5.3):
/// answers a live access token of this server's with the subject's claims.
/// </summary>
/// <remarks>
/// Validates the token as RFC 9068 §4 requires of any resource server, and asks the host's
/// <see cref="IClaimsProvider"/> fresh, so a subject it no longer serves is refused at the next call
/// rather than when the token expires.
/// </remarks>
internal sealed class UserInfoEndpoint(IOptions<AuthorizationServerOptions> options, CorsAllowlist allowedOrigins) : IZeeKayDaEndpoint
{
    private const string DefaultPath = "connect/userinfo";
    private const string BearerScheme = "Bearer";
    private const string AccessTokenFormField = "access_token";
    private const string FormUrlEncoded = "application/x-www-form-urlencoded";

    /// <inheritdoc/>
    /// <remarks>Served and published only with the authorization code grant, the only flow with an end user.</remarks>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        if (!options.Value.GrantTypesSupported.Contains(GrantType.AuthorizationCode))
            return;

        var issuerUri = EndpointRouteHelper.GetIssuerUri(options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri, options.Value.UserInfoEndpoint.Uri, DefaultPath);

        Delegate handler = HandleAsync;
        endpoints.MapMethods(endpointUri.AbsolutePath, [HttpMethods.Get, HttpMethods.Post], handler)
            .RequireIssuerHost(endpointUri)
            .ExemptFromHostAuthorization();

        // The Authorization header is not CORS-safelisted, so a browser preflights first.
        Delegate preflight = HandlePreflight;
        endpoints.MapMethods(endpointUri.AbsolutePath, [HttpMethods.Options], preflight)
            .RequireIssuerHost(endpointUri)
            .ExemptFromHostAuthorization();
    }

    internal IResult HandlePreflight(HttpContext context)
    {
        CorsHeaders.ApplyPreflight(
            context,
            allowedOrigins,
            methods: "GET, POST, OPTIONS",
            headers: "Authorization, Content-Type");

        return Results.StatusCode(StatusCodes.Status204NoContent);
    }

    internal async Task<IResult> HandleAsync(
        HttpContext context,
        AccessTokenValidator tokens,
        ValidatedClientResolver clients,
        GrantClaimsResolver claims)
    {
        CorsHeaders.ApplyOrigin(context, allowedOrigins);

        var authorization = await AuthorizeAsync(context, tokens, clients).ConfigureAwait(false);
        if (authorization is not Authorization.Caller caller)
            return ((Authorization.Refused)authorization).Response(context);

        // No family id: there is no grant here, only a token that proves one existed.
        var resolved = await claims.ResolveAsync(
            context,
            new ClaimsRequest(caller.Client, caller.Token.Subject, caller.Token.Scopes, FamilyId: null, ClaimsDestination.UserInfo))
            .ConfigureAwait(false);

        return resolved switch
        {
            GrantClaimsOutcome.Issue issue => UserInfoResponses.Claims(context, Body(caller.Token.Subject, issue.Claims)),
            GrantClaimsOutcome.SubjectInvalid => UserInfoResponses.InvalidToken(context),
            _ => UserInfoResponses.ServerError(context),
        };
    }

    /// <summary>
    /// Everything the request must prove before a claim is fetched: that it presented one
    /// well-formed bearer token, that this server issued it and it is still live and addressed
    /// here, that it carries <c>openid</c>, and that the client it names is still registered.
    /// </summary>
    private static async ValueTask<Authorization> AuthorizeAsync(
        HttpContext context, AccessTokenValidator tokens, ValidatedClientResolver clients)
    {
        var presented = await ReadAccessTokenAsync(context).ConfigureAwait(false);
        if (presented.Error is { } error)
            return new Authorization.Refused(error);

        if (tokens.Validate(presented.AccessToken) is not { } token)
            return new Authorization.Refused(UserInfoResponses.InvalidToken);

        // OIDC Core §5.3.1; its own code (RFC 6750 §3.1), since the client can fix it by asking for the scope.
        if (!token.Scopes.Contains(StandardScopes.OpenId.Name, StringComparer.Ordinal))
            return new Authorization.Refused(UserInfoResponses.InsufficientScope);

        // A registration gone or no longer valid takes the grant behind the token with it.
        var client = await clients.FindClientAsync(token.ClientId, context.RequestAborted).ConfigureAwait(false);

        return client is null
            ? new Authorization.Refused(UserInfoResponses.InvalidToken)
            : new Authorization.Caller(token, client);
    }

    /// <summary>
    /// <c>sub</c> and the claims the granted scopes and the client unlock at userinfo. OpenID
    /// Connect Core §5.3.2 requires <c>sub</c>, and selection has already dropped every reserved
    /// name from the subject claims, so it cannot be overwritten here.
    /// </summary>
    private static IReadOnlyDictionary<string, ClaimValue> Body(string subject, SelectedClaims claims)
    {
        var body = new Dictionary<string, ClaimValue>(claims.UserInfo.Count + 1, StringComparer.Ordinal)
        {
            ["sub"] = subject,
        };

        foreach (var (name, value) in claims.UserInfo)
            body.Add(name, value);

        return body;
    }

    /// <summary>
    /// The token RFC 6750 lets this endpoint read: the <c>Authorization: Bearer</c> header (§2.1)
    /// or, on a form POST, the <c>access_token</c> field (§2.2). The URI query parameter of §2.3
    /// is not read — it is deprecated there and puts a live credential in logs and referrers.
    /// </summary>
    /// <remarks>
    /// "Used" is kept apart from "well-formed" because RFC 6750 §3.1 answers them differently; merged, a
    /// repeated <c>access_token</c> field would read as none and escape the present-once check.
    /// </remarks>
    private static async ValueTask<PresentedToken> ReadAccessTokenAsync(HttpContext context)
    {
        var header = BearerHeader(context.Request.Headers);
        var form = await FormAccessTokenAsync(context).ConfigureAwait(false);

        if (header.Used && form.Used)
        {
            return PresentedToken.Rejected(response => UserInfoResponses.InvalidRequest(
                response, "The access token was presented both in the Authorization header and in the request body."));
        }

        if (!header.Used && !form.Used)
            return PresentedToken.Rejected(UserInfoResponses.MissingToken);

        return (header.Used ? header : form).Token is { } token
            ? PresentedToken.Accepted(token)
            : PresentedToken.Rejected(response => UserInfoResponses.InvalidRequest(
                response, "The access token was not presented as a single well-formed value."));
    }

    /// <summary>
    /// The <c>Authorization: Bearer</c> transport. More than one <c>Authorization</c> header is
    /// malformed whatever the schemes name — RFC 9110 §11.6.2 allows one — as is a Bearer header
    /// with nothing after the scheme. A single header naming another scheme does not use this
    /// transport at all, and draws the bare challenge that names the scheme this endpoint wants.
    /// </summary>
    private static Transport BearerHeader(IHeaderDictionary headers)
    {
        var authorization = headers.Authorization;

        if (authorization.Count == 0)
            return Transport.Unused;

        if (authorization.Count > 1)
            return Transport.Malformed;

        if (!IsBearer(authorization[0]))
            return Transport.Unused;

        return authorization[0]![BearerScheme.Length..].Trim() is { Length: > 0 } token
            ? Transport.Carrying(token)
            : Transport.Malformed;
    }

    /// <summary>The scheme, followed by the end of the value or the space separating its token.</summary>
    private static bool IsBearer(string? value) =>
        value is not null
        && value.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase)
        && (value.Length == BearerScheme.Length || char.IsWhiteSpace(value[BearerScheme.Length]));

    /// <summary>
    /// The <c>access_token</c> form field of a form-encoded POST (RFC 6750 §2.2). A body in any
    /// other media type does not use this transport at all; one that claims to be a form and
    /// cannot be read, or that repeats the field, uses it malformed.
    /// </summary>
    private static async ValueTask<Transport> FormAccessTokenAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || !IsFormUrlEncoded(context.Request))
            return Transport.Unused;

        IFormCollection form;
        try
        {
            form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException)
        {
            return Transport.Malformed;
        }

        if (!form.TryGetValue(AccessTokenFormField, out var field))
            return Transport.Unused;

        return field is { Count: 1 } && field[0] is { Length: > 0 } token
            ? Transport.Carrying(token)
            : Transport.Malformed;
    }

    private static bool IsFormUrlEncoded(HttpRequest request) =>
        Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType) &&
        contentType.MediaType.Equals(FormUrlEncoded, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// One way of presenting the token: whether the request used it at all, and the single token
    /// it carried, which is <see langword="null"/> when it was used but not well-formed.
    /// </summary>
    private readonly record struct Transport(bool Used, string? Token)
    {
        public static Transport Unused => new(false, null);

        public static Transport Malformed => new(true, null);

        public static Transport Carrying(string token) => new(true, token);
    }

    /// <summary>What authorizing a request came to. Closed: it proved a caller, or it did not.</summary>
    private abstract record Authorization
    {
        private Authorization()
        {
        }

        /// <summary>The token the request proved, and the client registration it names.</summary>
        public sealed record Caller(ValidatedAccessToken Token, IClient Client) : Authorization;

        /// <summary>The refusal to answer with, already chosen.</summary>
        public sealed record Refused(Func<HttpContext, IResult> Response) : Authorization;
    }

    /// <summary>The token the request presented, or the refusal that replaces it.</summary>
    private readonly record struct PresentedToken(string? AccessToken, Func<HttpContext, IResult>? Error)
    {
        public static PresentedToken Accepted(string accessToken) => new(accessToken, null);

        public static PresentedToken Rejected(Func<HttpContext, IResult> error) => new(null, error);
    }
}
