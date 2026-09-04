using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What every successful sign-in ends in, whichever page or provider produced the principal:
/// promotion to the SSO session, the authentication recorded on the interaction context, and the
/// continuation of the flow.
/// </summary>
internal sealed class SignInCompletion
{
    private readonly AuthorizationFlow _flow;
    private readonly LocalErrorResponse _localError;

    public SignInCompletion(AuthorizationFlow flow, LocalErrorResponse localError)
    {
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(localError);

        _flow = flow;
        _localError = localError;
    }

    /// <summary>
    /// Terminal: writes and commits the response.
    /// </summary>
    /// <remarks>
    /// Consent and code issuance replace the <c>501</c> this currently ends in. The session and
    /// the authenticated context are already written, so what those stages add is the response,
    /// not the state.
    /// </remarks>
    public async Task CompleteAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ClaimsPrincipal principal,
        IReadOnlyList<string> authenticationMethods,
        string? providerScheme)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        // Responses on this path carry protocol material once code issuance lands, and a cached
        // sign-in response is a stolen one.
        context.Response.Headers.CacheControl = "no-store";

        var state = await _flow.PromoteAsync(context, principal, authenticationMethods).ConfigureAwait(false);

        var authenticated = requestContext with
        {
            SsoSessionId = state.SessionId,
            Subject = state.Subject,
            AuthTime = state.AuthTime,
            Amr = state.Amr,
            ProviderScheme = providerScheme,
        };

        if (!_flow.TryPersist(context, authenticated))
        {
            // Only reachable for a context already near the size ceiling before a few small
            // fields were added to it. The session is established either way — what cannot
            // continue is this authorization request, so it fails where the oversize did.
            _flow.Clear(context);
            await TerminalResponse.WriteAsync(
                context,
                _localError.Render(
                    context,
                    AuthorizeRequestErrors.InvalidRequest,
                    "The authorization request is too large to process."))
                .ConfigureAwait(false);

            return;
        }

        await TerminalResponse.WriteAsync(context, PreAlphaNotImplementedResult.Result).ConfigureAwait(false);
    }
}
