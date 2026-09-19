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
/// <para>
/// A protected resource, validated as RFC 9068 §4 obliges any resource server to validate one of
/// these tokens, rather than by trusting the issuer of a token it happens to be able to verify.
/// Nothing is read from a store: the token names the subject, the client and the granted scopes,
/// and the claims come from the host's <see cref="IClaimsProvider"/>, asked fresh.
/// </para>
/// <para>
/// Asking fresh is what bounds staleness. A token stays usable until it expires however the grant
/// behind it ended, so a subject the provider no longer serves is refused here at the next call
/// rather than at the end of the token's life.
/// </para>
/// </remarks>
internal sealed class UserInfoEndpoint : IZeeKayDaEndpoint
{
    private const string DefaultPath = "connect/userinfo";
    private const string BearerScheme = "Bearer";
    private const string AccessTokenFormField = "access_token";
    private const string FormUrlEncoded = "application/x-www-form-urlencoded";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly HashSet<string> _allowedOrigins;

    public UserInfoEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        // Config values are already validated and canonicalized to lowercase by startup validation.
        _allowedOrigins = new HashSet<string>(options.Value.CorsOrigins, StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Served on the same condition as the authorization endpoint, and published on the same
    /// condition too, so the metadata and the route never disagree: only that flow issues an
    /// access token for an end user, and userinfo has nothing to answer without one.
    /// </remarks>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        if (!_options.Value.GrantTypesSupported.Contains(GrantType.AuthorizationCode))
            return;

        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri, _options.Value.UserInfoEndpoint.Uri, DefaultPath);

        // AllowAnonymous so a host-wide authorization fallback policy cannot challenge with the
        // host's own scheme: the bearer token is this endpoint's authentication, not the host's.
        Delegate handler = HandleAsync;
        endpoints.MapMethods(endpointUri.AbsolutePath, [HttpMethods.Get, HttpMethods.Post], handler)
            .RequireIssuerHost(endpointUri)
            .AllowAnonymous();

        // A browser sends the token in an Authorization header, which is not a CORS-safelisted
        // request header, so it preflights first and never reaches the handler above.
        Delegate preflight = HandlePreflight;
        endpoints.MapMethods(endpointUri.AbsolutePath, [HttpMethods.Options], preflight)
            .RequireIssuerHost(endpointUri)
            .AllowAnonymous();
    }

    internal IResult HandlePreflight(HttpContext context)
    {
        CorsHeaders.ApplyPreflight(
            context,
            _allowedOrigins,
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
        CorsHeaders.ApplyOrigin(context, _allowedOrigins);

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

        // OpenID Connect Core §5.3.1: userinfo answers a token issued under the openid scope.
        // Distinct from an invalid token, because the client can act on this one by asking for
        // the scope, and RFC 6750 §3.1 gives it its own code.
        if (!token.Scopes.Contains(StandardScopes.OpenId.Name, StringComparer.Ordinal))
            return new Authorization.Refused(UserInfoResponses.InsufficientScope);

        // The client the token was issued to decides its own claim additions. A registration that
        // is gone, or no longer validates, means the grant behind the token is gone with it.
        var client = await clients.FindByClientIdAsync(token.ClientId, context.RequestAborted).ConfigureAwait(false);

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
    /// Whether a transport was <em>used</em> is decided separately from whether it carried one
    /// well-formed token, because §3.1 answers the two differently: using both transports, or
    /// using one malformed, is <c>invalid_request</c>, while using neither is the bare challenge.
    /// Collapsing them would let a repeated <c>access_token</c> field read as no field at all, and
    /// so escape the check that a request may present its token exactly once.
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
        public sealed record Caller(ValidatedAccessToken Token, IClientRegistration Client) : Authorization;

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
