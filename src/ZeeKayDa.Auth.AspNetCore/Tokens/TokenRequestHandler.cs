using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tokens;

/// <summary>
/// The token endpoint's request pipeline (RFC 6749 §3.2): parse the form, authenticate the
/// client, check it may use the grant, then hand the grant its request. Every refusal before
/// the grant costs no store I/O.
/// </summary>
internal sealed class TokenRequestHandler
{
    private readonly CompositeClientAuthenticator _authenticator;
    private readonly AuthorizationCodeGrant _grant;

    public TokenRequestHandler(CompositeClientAuthenticator authenticator, AuthorizationCodeGrant grant)
    {
        ArgumentNullException.ThrowIfNull(authenticator);
        ArgumentNullException.ThrowIfNull(grant);

        _authenticator = authenticator;
        _grant = grant;
    }

    public async Task<IResult> HandleAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        TokenResponses.MarkUncacheable(context.Response);

        if (!context.Request.HasFormContentType)
            return TokenResponses.Error(TokenError.InvalidRequest("A token request must use application/x-www-form-urlencoded serialization."));

        var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);

        if (!TokenRequest.TryParse(form, out var request, out var error))
            return TokenResponses.Error(error);

        // The client is whoever the request names: the form's client_id, or the Basic header's
        // username when the form carries none. The authenticator refuses the two disagreeing.
        if (IdentifyClient(request, context.Request.Headers) is not { } clientId)
            return TokenResponses.InvalidClient(context);

        var authentication = await _authenticator.AuthenticateAsync(clientId, context, context.RequestAborted).ConfigureAwait(false);
        if (!authentication.Authenticated)
            return TokenResponses.InvalidClient(context);

        // Resolved per request, like the stores the grant reads: the repository is a host
        // registration that startup verification, not route mapping, confirms is present.
        var clients = context.RequestServices.GetRequiredService<ValidatedClientResolver>();
        if (await clients.FindByClientIdAsync(clientId, context.RequestAborted).ConfigureAwait(false) is not { } client)
            return TokenResponses.InvalidClient(context);

        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
            return TokenResponses.Error(new TokenError(TokenRequestErrors.UnauthorizedClient, "The client is not authorized to use the authorization_code grant type."));

        return await _grant.ExchangeAsync(context, request, client).ConfigureAwait(false);
    }

    private static string? IdentifyClient(TokenRequest request, IHeaderDictionary headers)
    {
        if (request.ClientId is { } fromForm)
            return fromForm;

        if (!BasicAuthorizationHeader.IsPresent(headers) || !BasicAuthorizationHeader.TryParse(headers, out var username, out _))
            return null;

        return username.Length > 0 ? username : null;
    }
}
