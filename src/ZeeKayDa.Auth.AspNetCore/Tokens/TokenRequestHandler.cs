using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// The token endpoint's request pipeline (RFC 6749 §3.2): parse the form, check the server
/// serves the grant, authenticate the client, check it may use the grant, then hand the grant
/// its request. Every refusal before the grant costs no store I/O.
/// </summary>
internal sealed class TokenRequestHandler
{
    private const string FormUrlEncoded = "application/x-www-form-urlencoded";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly CompositeClientAuthenticator _authenticator;
    private readonly AuthorizationCodeGrant _grant;

    public TokenRequestHandler(
        IOptions<AuthorizationServerOptions> options,
        CompositeClientAuthenticator authenticator,
        AuthorizationCodeGrant grant)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authenticator);
        ArgumentNullException.ThrowIfNull(grant);

        _options = options;
        _authenticator = authenticator;
        _grant = grant;
    }

    public async Task<IResult> HandleAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        TokenResponses.MarkUncacheable(context.Response);

        // Exactly the serialization RFC 6749 §4.1.3 names, not any form the host could parse.
        if (!IsFormUrlEncoded(context.Request))
            return TokenResponses.Error(TokenError.InvalidRequest("A token request must use application/x-www-form-urlencoded serialization."));

        if (await ReadFormAsync(context).ConfigureAwait(false) is not { } form)
            return TokenResponses.Error(TokenError.InvalidRequest("The request body could not be read as a form."));

        if (!TokenRequest.TryParse(form, out var request, out var error))
            return TokenResponses.Error(error);

        // The server's own grant list is the first gate, before any client is named: a host that
        // no longer serves the code grant must not redeem a code that outlived the change.
        if (!ServesCodeGrant())
            return TokenResponses.Error(new TokenError(TokenRequestErrors.UnsupportedGrantType, "The authorization_code grant type is not supported by this server."));

        // The client is whoever the request names: the form's client_id, or the Basic header's
        // username when the form carries none. The authenticator refuses the two disagreeing.
        if (IdentifyClient(request, context.Request.Headers) is not { } clientId)
            return TokenResponses.InvalidClient(context);

        // The registration the credential was checked against is the one every later decision
        // reads; a second lookup could return one nobody authenticated.
        var authentication = await _authenticator.AuthenticateAsync(clientId, context, context.RequestAborted).ConfigureAwait(false);
        if (authentication.Client is not { } client)
            return TokenResponses.InvalidClient(context);

        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
            return TokenResponses.Error(new TokenError(TokenRequestErrors.UnauthorizedClient, "The client is not authorized to use the authorization_code grant type."));

        return await _grant.ExchangeAsync(context, request, client).ConfigureAwait(false);
    }

    private static bool IsFormUrlEncoded(HttpRequest request) =>
        MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType) &&
        contentType.MediaType.Equals(FormUrlEncoded, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A body the form reader refuses, over the host's form limits or malformed, is the client's
    /// mistake and is answered as one, with the headers already written left intact.
    /// </summary>
    private static async ValueTask<IFormCollection?> ReadFormAsync(HttpContext context)
    {
        try
        {
            return await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException)
        {
            return null;
        }
    }

    private bool ServesCodeGrant() =>
        _options.Value.GrantTypesSupported.Contains(GrantType.AuthorizationCode);

    private static string? IdentifyClient(TokenRequest request, IHeaderDictionary headers)
    {
        if (request.ClientId is { } fromForm)
            return fromForm;

        if (!BasicAuthorizationHeader.IsPresent(headers) || !BasicAuthorizationHeader.TryParse(headers, out var username, out _))
            return null;

        return username.Length > 0 ? username : null;
    }
}
