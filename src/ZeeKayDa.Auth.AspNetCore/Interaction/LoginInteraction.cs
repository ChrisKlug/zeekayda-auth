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
    /// <summary>
    /// What the client is told when the host cancels without saying why. Names the stage as well
    /// as the outcome, so a client can tell this apart from a consent denial or a policy refusal —
    /// all three are <c>access_denied</c> on the wire.
    /// </summary>
    private const string CancelledAtSignIn = "The user cancelled the request at the sign-in page.";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthorizationFlow _flow;
    private readonly LocalErrorResponse _localError;
    private readonly ClientErrorRedirect _clientError;

    public LoginInteraction(
        IHttpContextAccessor httpContextAccessor,
        AuthorizationFlow flow,
        LocalErrorResponse localError,
        ClientErrorRedirect clientError)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(localError);
        ArgumentNullException.ThrowIfNull(clientError);

        _httpContextAccessor = httpContextAccessor;
        _flow = flow;
        _localError = localError;
        _clientError = clientError;
    }

    /// <inheritdoc/>
    public async Task SignInAsync(ClaimsPrincipal principal, params string[] authenticationMethods)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        // Caught here rather than at the claim write so the blame lands on the caller's
        // argument, not on a malformed session cookie several frames later.
        if (authenticationMethods.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "An authentication method reference is null or blank. Pass a value such as "
                + "AuthenticationMethods.Password, or pass none to omit the amr claim.",
                nameof(authenticationMethods));

        var context = _httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException(
                "ILoginInteraction requires an active HTTP request. Resolve it from request services " +
                "inside the login page, not from a background service.");

        var requestContext = await ResolveInteractionAsync(context).ConfigureAwait(false);

        // Responses on this path carry protocol material once code issuance lands (#87), and a
        // cached sign-in response is a stolen one.
        context.Response.Headers.CacheControl = "no-store";

        var state = await _flow.PromoteAsync(context, principal, authenticationMethods).ConfigureAwait(false);

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

    /// <inheritdoc/>
    public Task DenyAsync() => DenyCoreAsync(CancelledAtSignIn);

    /// <inheritdoc/>
    public Task DenyAsync(string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        // Guarded here, at the public boundary, rather than where it is written onto the query
        // string: a host that supplies an unusable description has made a mistake at this call,
        // and finding out at the redirect would blame the framework's own error path.
        if (!IsLegalErrorDescription(description))
            throw new ArgumentException(
                "An error_description may only carry printable US-ASCII, excluding the double quote " +
                "and the backslash (RFC 6749 §4.1.2.1). Rewrite the text without the offending " +
                "characters — a client cannot read what the response cannot legally carry.",
                nameof(description));

        return DenyCoreAsync(description);
    }

    /// <summary>
    /// Ends the interaction the request is addressed to, telling the client the user did not
    /// authorize it. Resolution and the <c>zkd_i</c> binding are exactly as they are for a
    /// sign-in: a deny that could be aimed at another tab's request is a cross-tab denial of
    /// service.
    /// </summary>
    private async Task DenyCoreAsync(string description)
    {
        var context = _httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException(
                "ILoginInteraction requires an active HTTP request. Resolve it from request services " +
                "inside the login page, not from a background service.");

        var requestContext = await ResolveInteractionAsync(context).ConfigureAwait(false);

        context.Response.Headers.CacheControl = "no-store";

        // Discarded before the response is written, so a cancelled request cannot be resumed by a
        // later sign-in picking the context back up.
        _flow.Clear(context);

        // The destination is the redirect URI phase 1 matched against the registration, read back
        // out of the encrypted context — never anything this request supplied. No session is
        // promoted and none is read: a user cancelling here is not signed in, and a user who was
        // already signed in elsewhere stays that way.
        await _clientError
            .To(requestContext.RedirectUri, AuthorizeRequestErrors.AccessDenied, description, requestContext.State)
            .ExecuteAsync(context)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// RFC 6749 §4.1.2.1 confines <c>error_description</c> to %x20-21 / %x23-5B / %x5D-7E —
    /// printable US-ASCII without the double quote or the backslash.
    /// </summary>
    private static bool IsLegalErrorDescription(string description) =>
        description.All(c => c is >= ' ' and <= '~' and not '"' and not '\\');

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
