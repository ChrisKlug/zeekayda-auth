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

    /// <summary>How long a browser may cache the preflight. One hour, the common ceiling.</summary>
    private const int PreflightMaxAgeSeconds = 3600;

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

    private IResult HandlePreflight(HttpContext context)
    {
        CorsHeaders.ApplyPreflight(
            context,
            _allowedOrigins,
            methods: "GET, POST, OPTIONS",
            headers: "Authorization, Content-Type",
            PreflightMaxAgeSeconds);

        return Results.StatusCode(StatusCodes.Status204NoContent);
    }

    private async Task<IResult> HandleAsync(
        HttpContext context,
        AccessTokenValidator tokens,
        ValidatedClientResolver clients,
        GrantClaimsResolver claims)
    {
        CorsHeaders.ApplyOrigin(context, _allowedOrigins);

        var presented = await ReadAccessTokenAsync(context).ConfigureAwait(false);
        if (presented.Error is { } error)
            return error(context);

        if (tokens.Validate(presented.AccessToken) is not { } token)
            return UserInfoResponses.InvalidToken(context);

        // OpenID Connect Core §5.3.1: userinfo answers a token issued under the openid scope.
        // Distinct from an invalid token, because the client can act on this one by asking for
        // the scope, and RFC 6750 §3.1 gives it its own code.
        if (!token.Scopes.Contains(StandardScopes.OpenId.Name, StringComparer.Ordinal))
            return UserInfoResponses.InsufficientScope(context);

        // The client the token was issued to decides its own claim additions. A registration that
        // is gone, or no longer validates, means the grant behind the token is gone with it.
        var client = await clients.FindByClientIdAsync(token.ClientId, context.RequestAborted).ConfigureAwait(false);
        if (client is null)
            return UserInfoResponses.InvalidToken(context);

        // No family id: there is no grant here, only a token that proves one existed.
        var resolved = await claims.ResolveAsync(
            context, client, token.Subject, token.Scopes, familyId: null).ConfigureAwait(false);

        return resolved switch
        {
            GrantClaimsOutcome.Issue issue => UserInfoResponses.Claims(context, Body(token.Subject, issue.Claims)),
            GrantClaimsOutcome.SubjectInvalid => UserInfoResponses.InvalidToken(context),
            _ => UserInfoResponses.ServerError(context),
        };
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
    /// Presenting more than one is <c>invalid_request</c> (§3.1), as is presenting none of them.
    /// </summary>
    private static async ValueTask<PresentedToken> ReadAccessTokenAsync(HttpContext context)
    {
        var fromHeader = BearerToken(context.Request.Headers);
        var fromForm = await FormAccessTokenAsync(context).ConfigureAwait(false);

        if (fromHeader is not null && fromForm is not null)
        {
            return PresentedToken.Rejected(response => UserInfoResponses.InvalidRequest(
                response, "The access token was presented both in the Authorization header and in the request body."));
        }

        return (fromHeader ?? fromForm) is { } presented
            ? PresentedToken.Accepted(presented)
            : PresentedToken.Rejected(UserInfoResponses.MissingToken);
    }

    /// <summary>
    /// The token of exactly one <c>Authorization: Bearer</c> header. Two headers, or a scheme this
    /// endpoint does not accept, present no bearer token at all.
    /// </summary>
    private static string? BearerToken(IHeaderDictionary headers)
    {
        var authorization = headers.Authorization;
        if (authorization.Count != 1 || authorization[0] is not { } value)
            return null;

        if (!value.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase))
            return null;

        var remainder = value[BearerScheme.Length..];
        if (remainder.Length == 0 || !char.IsWhiteSpace(remainder[0]))
            return null;

        return remainder.Trim() is { Length: > 0 } token ? token : null;
    }

    /// <summary>
    /// The <c>access_token</c> form field of a form-encoded POST (RFC 6750 §2.2). A body in any
    /// other media type is not read at all, and one the form reader refuses carries no field.
    /// </summary>
    private static async ValueTask<string?> FormAccessTokenAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || !IsFormUrlEncoded(context.Request))
            return null;

        IFormCollection form;
        try
        {
            form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException)
        {
            return null;
        }

        return form[AccessTokenFormField] is { Count: 1 } field && field[0] is { Length: > 0 } token
            ? token
            : null;
    }

    private static bool IsFormUrlEncoded(HttpRequest request) =>
        Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType) &&
        contentType.MediaType.Equals(FormUrlEncoded, StringComparison.OrdinalIgnoreCase);

    /// <summary>The token the request presented, or the refusal that replaces it.</summary>
    private readonly record struct PresentedToken(string? AccessToken, Func<HttpContext, IResult>? Error)
    {
        public static PresentedToken Accepted(string accessToken) => new(accessToken, null);

        public static PresentedToken Rejected(Func<HttpContext, IResult> error) => new(null, error);
    }
}
