using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host logout page's confirmation of a sign-out. One of the per-page interaction services:
/// the host owns the page, this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// Used by the page at <c>EndSessionEndpoint.LogoutPath</c>. The framework redirects there when
/// the user must be asked before being signed out, carrying a <c>zkd_i</c> query parameter the
/// page must preserve across its own form post, on the same terms as the login page.
/// </para>
/// <para>
/// There is nothing to call when the user declines. A sign-out has no error response to the
/// client, so a "stay signed in" button can go wherever the host likes, and the unanswered
/// sign-out expires on its own.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When <see cref="SignOutAsync"/>
/// finds no sign-out left to complete — the request carries no <c>zkd_i</c>; the sign-out expired,
/// was already completed or was started in another browser; or the browser no longer holds the
/// session it was started for — the framework answers the request itself: with the signed-out page
/// when the browser holds no session, and with the error page, with
/// <see cref="AuthorizationErrorKind.NothingToContinue"/>, when it is still signed in. Nobody is
/// signed out by such a request. The call is terminal either way.
/// </para>
/// </remarks>
public sealed class LogoutInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly LogoutRequestStore _requests;
    private readonly EndSessionResponses _responses;
    private readonly SsoSession _session;
    private readonly NothingToContinue _nothingToContinue;

    internal LogoutInteraction(
        IHttpContextAccessor httpContextAccessor,
        LogoutRequestStore requests,
        EndSessionResponses responses,
        SsoSession session,
        NothingToContinue nothingToContinue)
    {
        _httpContextAccessor = httpContextAccessor;
        _requests = requests;
        _responses = responses;
        _session = session;
        _nothingToContinue = nothingToContinue;
    }

    /// <summary>
    /// Returns the sign-out the page is asked to confirm, for the page to render.
    /// </summary>
    /// <remarks>
    /// The response this is read from is stamped <c>frame-ancestors 'none'</c>,
    /// <c>X-Frame-Options: DENY</c> and <c>no-store</c>, so the page taking a one-click decision
    /// cannot be framed or cached. A page that renders without calling this — a fixed "Sign out?"
    /// page that only posts — gets none of those headers and must set its own.
    /// </remarks>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no sign-out to confirm: the request carries no <c>zkd_i</c>, or names one this
    /// browser is not carrying — it expired, was already completed, or was started in another
    /// browser. Or the browser no longer holds the session the sign-out was started for, on the
    /// same terms as <see cref="SignOutAsync"/>: the sign-out could not complete anyway, and
    /// <see cref="LogoutRequest.Subject"/> names the user it was started for, who is no longer the
    /// one at the browser. A page that wants to render its own message for these cases calls
    /// <see cref="TryGetRequestAsync"/> instead.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<LogoutRequest> GetRequestAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();

        cancellationToken.ThrowIfCancellationRequested();

        // The page takes a one-click decision, so it renders framed by nobody and cached by nothing
        // — stamped before the read, so a page rendering its own "nothing to confirm" is covered too.
        RenderedPage.Protect(context.Response);
        var request = await ResolveAddressedAsync(context, cancellationToken).ConfigureAwait(false);

        // Checked here and not only at SignOutAsync: the request names the user it was started for,
        // and a confirmation left open across a fresh sign-in would hand the new user the previous
        // one's subject. Refusing the render is also honest — the sign-out it asks about can no
        // longer complete.
        await RequireAskedSessionAsync(context, request, cancellationToken).ConfigureAwait(false);

        if (request.ClientId is null)
            return new LogoutRequest(client: null, request.Subject);

        var client = await FindClientAsync(context, request.ClientId, cancellationToken).ConfigureAwait(false);
        return new LogoutRequest(new ClientInformation(request.ClientId, client?.DisplayName), request.Subject);
    }

    /// <summary>
    /// Returns the sign-out the page is asked to confirm, or <see langword="null"/> when there is
    /// none — for a page that renders its own "nothing to confirm" message.
    /// </summary>
    /// <remarks>
    /// Exactly <see cref="GetRequestAsync"/>, including the headers it stamps, except that each case
    /// <see cref="GetRequestAsync"/> reports with <see cref="ZeeKayDaInteractionException"/> returns
    /// <see langword="null"/> instead. A request with no <c>zkd_i</c> is logged as a warning, since
    /// a form that drops it looks like this on every submission.
    /// </remarks>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<LogoutRequest?> TryGetRequestAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await GetRequestAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (NothingToContinueException missing)
        {
            _nothingToContinue.Log("logout", missing);
            return null;
        }
    }

    /// <summary>
    /// Signs the user out and sends them on: to the client's registered post-logout redirect URI
    /// when the sign-out named one, carrying the client's <c>state</c>, and to the signed-out page
    /// otherwise. This is the Sign out button.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. A Razor Pages handler or controller action can simply end after it:
    /// the framework skips MVC's result, including one the handler returns. Anywhere else,
    /// returning a result of your own after calling it throws, because the response has already
    /// started.
    /// </para>
    /// <para>
    /// The SSO session ends, and so does every authorization request this browser still has in
    /// flight. The redirect URI is checked again against the client's registration as it stands
    /// now, so one the operator removed while the page was open is not used.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A sign-out wired to the <c>GET</c> that renders the page would sign the
    /// user out the moment they arrived, which is exactly what the confirmation exists to prevent.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be read. Fail-closed: nobody was signed out.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task SignOutAsync()
    {
        var context = RequireStateChangingRequest();
        await _nothingToContinue.SignOutStepAsync(context, () => ConfirmAsync(context)).ConfigureAwait(false);
    }

    private async Task ConfirmAsync(HttpContext context)
    {
        var request = await ResolveAddressedAsync(context, context.RequestAborted).ConfigureAwait(false);
        await RequireAskedSessionAsync(context, request, context.RequestAborted).ConfigureAwait(false);

        // Checked against the registration as it stands now rather than remembered from when the
        // sign-out arrived: an operator who removes a redirect URI means nobody to be sent there.
        var client = request.ClientId is null
            ? null
            : await FindClientAsync(context, request.ClientId, context.RequestAborted).ConfigureAwait(false);
        var redirect = PostLogoutRedirect.For(client, request.PostLogoutRedirectUri, request.State);

        await _requests.DeleteAsync(context, request.Id, context.RequestAborted).ConfigureAwait(false);
        var result = await _responses.SignOutAsync(context, redirect).ConfigureAwait(false);

        context.Response.Headers.CacheControl = "no-store";
        await result.ExecuteAsync(context).ConfigureAwait(false);
        await context.Response.StartAsync().ConfigureAwait(false);
        TerminalResponse.MarkCommitted(context);
    }

    /// <summary>
    /// The sign-out this request is addressed to: named by <c>zkd_i</c> and bound to this browser.
    /// </summary>
    private async ValueTask<LogoutRequestContext> ResolveAddressedAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var interactionId = await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false)
            ?? throw new NothingToContinueException(
                NothingToContinueReason.NoInteractionId,
                $"This request carries no '{InteractionHandoff.InteractionIdParameter}' parameter, so there is " +
                "no sign-out to confirm. The framework adds it to the URL it redirects the logout page to; a " +
                "form that regenerates its action from routing drops it, and must pass it back explicitly " +
                $"(asp-route-{InteractionHandoff.InteractionIdParameter}).");

        var request = await _requests.ReadAsync(context, interactionId, cancellationToken).ConfigureAwait(false);
        if (request is not null)
            return request;

        // Nothing is left for this binding to address, so its secret is retired rather than left
        // live for the rest of the cookie's life, taking a per-browser slot from a live tab.
        await _requests.DeleteAsync(context, interactionId, cancellationToken).ConfigureAwait(false);

        throw new NothingToContinueException(
                NothingToContinueReason.NotFound,
                "There is no sign-out waiting to be confirmed with this identifier for this browser. It has " +
                "expired or already completed, the page was reached without going through the end-session " +
                "endpoint, or the sign-out was started in another browser.");
    }

    /// <summary>
    /// Refuses unless the browser still holds the session the sign-out was started for. A
    /// confirmation left open across a sign-out or a fresh sign-in would otherwise end a session
    /// nobody was asked about, and the answer to a question about a session that has since ended
    /// is not an instruction about its replacement. Reading the sign-out is gated on it too, so
    /// the subject it carries is only ever shown to the browser it was stored for.
    /// </summary>
    private async ValueTask RequireAskedSessionAsync(
        HttpContext context,
        LogoutRequestContext request,
        CancellationToken cancellationToken)
    {
        var session = await _session.ReadAsync(context).ConfigureAwait(false);
        if (session is not null && string.Equals(session.SessionId, request.SsoSessionId, StringComparison.Ordinal))
            return;

        // One answer either way: a sign-out that cannot be completed is not left for a later try.
        await _requests.DeleteAsync(context, request.Id, cancellationToken).ConfigureAwait(false);

        throw new NothingToContinueException(
            NothingToContinueReason.SessionChanged,
            "The session this sign-out was started for is not the one this browser holds now — it has " +
            "already ended, or the user signed in again since being asked. Start the sign-out again.");
    }

    /// <summary>
    /// The client's validated registration, resolved from the request's services for the reason
    /// <c>AuthorizationFlow.ResolveClientAsync</c> gives; <see langword="null"/> when it is no
    /// longer registered.
    /// </summary>
    private static ValueTask<IClient?> FindClientAsync(HttpContext context, string clientId, CancellationToken cancellationToken) =>
        context.RequestServices.GetRequiredService<ValidatedClientResolver>().FindClientAsync(clientId, cancellationToken);

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "LogoutInteraction requires an active HTTP request. Resolve it from request services inside " +
            "the logout page, not from a background service.");

    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "A sign-out must come from a POST — the logout form's submission — not from the request " +
                "that renders the page. Wire SignOutAsync to the form's post handler.");
        }

        return context;
    }
}
