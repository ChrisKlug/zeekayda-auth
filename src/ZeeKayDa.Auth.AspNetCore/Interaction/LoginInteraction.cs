using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="ILoginInteraction"/> implementation: verifies the handoff, promotes the
/// principal to an SSO session, records the authentication on the interaction context, and
/// continues the flow.
/// </summary>
/// <remarks>
/// Every read and write here is addressed by the interaction identifier the request carried —
/// never by "the current interaction". That is what keeps the backing swappable: a store-backed
/// context (#603) reads <em>an</em> interaction by id, and this code already asks for one.
/// </remarks>
internal sealed class LoginInteraction : ILoginInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthorizationFlow _flow;
    private readonly LocalErrorResponse _localError;

    public LoginInteraction(
        IHttpContextAccessor httpContextAccessor,
        AuthorizationFlow flow,
        LocalErrorResponse localError)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(localError);

        _httpContextAccessor = httpContextAccessor;
        _flow = flow;
        _localError = localError;
    }

    /// <inheritdoc/>
    public async Task SignInAsync(ClaimsPrincipal principal, string amr)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(amr);

        var context = _httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException(
                "ILoginInteraction requires an active HTTP request. Resolve it from request services " +
                "inside the login page, not from a background service.");

        var requestContext = await ResolveInteractionAsync(context).ConfigureAwait(false);

        // Responses on this path carry protocol material once code issuance lands (#87), and a
        // cached sign-in response is a stolen one.
        context.Response.Headers.CacheControl = "no-store";

        var state = await _flow.PromoteAsync(context, principal, amr).ConfigureAwait(false);

        var authenticated = requestContext with
        {
            SsoSessionId = state.SessionId,
            Subject = state.Subject,
            AuthTime = state.AuthTime,
            Amr = state.Amr,
        };

        if (!_flow.TryPersist(context, authenticated))
        {
            // Only reachable for a context already near the size ceiling before four small fields
            // were added to it. The session is established either way — what cannot continue is
            // this authorization request, so it fails where the oversize did.
            _flow.Clear(context);
            await _localError
                .Render(
                    context,
                    AuthorizeRequestErrors.InvalidRequest,
                    "The authorization request is too large to process.")
                .ExecuteAsync(context)
                .ConfigureAwait(false);

            return;
        }

        // Consent (#86) and code issuance (#87) replace this. The session and the authenticated
        // context are already written, so what those slices add is the response, not the state.
        await PreAlphaNotImplementedResult.Result.ExecuteAsync(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Resolves the interaction this request is entitled to complete: the one the framework sent
    /// the user here for, named by <c>zkd_i</c> and confirmed against the identifier inside the
    /// encrypted context.
    /// </summary>
    private async ValueTask<AuthorizationRequestContext> ResolveInteractionAsync(HttpContext context)
    {
        var interactionId = await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                $"This request carries no '{InteractionHandoff.InteractionIdParameter}' parameter, so there " +
                "is no interaction to complete. The framework adds it to the URL it redirects the login " +
                "page to; a form that regenerates its action from routing drops it, and must pass it back " +
                $"explicitly (asp-route-{InteractionHandoff.InteractionIdParameter}).");

        var requestContext = _flow.Read(context)
            ?? throw new ZeeKayDaInteractionException(
                "There is no active interaction to complete. The authorization request has expired, or " +
                "the login page was reached without going through /connect/authorize.");

        if (!IdentifiersMatch(requestContext.Id, interactionId))
            throw new ZeeKayDaInteractionException(
                "The interaction this request names is not the one this browser is carrying. This is what " +
                "a second sign-in tab looks like: complete the authorization request that was started " +
                "most recently, or start a new one.");

        return requestContext;
    }

    /// <summary>
    /// Compares in fixed time. The identifier is never published — it lives inside the encrypted
    /// context and on the URL of the page the framework redirected to — so a comparison that
    /// leaked its bytes through timing would leak something the caller is not otherwise given.
    /// </summary>
    private static bool IdentifiersMatch(string expected, string supplied) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(supplied));
}
