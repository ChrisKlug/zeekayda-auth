using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host logout page's confirmation of a sign-out, at <c>EndSessionEndpoint.LogoutPath</c>. The
/// host owns the page; this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page must preserve the <c>zkd_i</c> query parameter it was reached with across its own form
/// post. There is nothing to call when the user declines: a sign-out has no error response to the
/// client, so a "stay signed in" button can go anywhere, and the unanswered sign-out expires.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When <see cref="SignOutAsync"/>
/// finds no sign-out left to complete — no <c>zkd_i</c>; the sign-out expired, was completed or
/// belongs to another browser; or the browser no longer holds the session it was started for — the
/// framework answers with the signed-out page when the browser holds no session, and with the error
/// page, with <see cref="AuthorizationErrorKind.NothingToContinue"/>, when it is still signed in.
/// Nobody is signed out by such a request.
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
    /// The response is stamped <c>frame-ancestors 'none'</c>, <c>X-Frame-Options: DENY</c> and
    /// <c>no-store</c> before the read, since the page takes a one-click decision. A page that renders
    /// without calling this — a fixed "Sign out?" page that only posts — must set its own.
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

        RenderedPage.Protect(context.Response);
        var request = await ResolveAddressedAsync(context, cancellationToken).ConfigureAwait(false);

        // At render too: the request carries the subject, which must not reach a user signed in since.
        var (sessions, _) = await RequireAskedSessionAsync(context, request, cancellationToken).ConfigureAwait(false);
        var accounts = sessions.Accounts.Select(SignedInAccount.Of).ToArray();

        if (request.ClientId is null)
            return new LogoutRequest(client: null, request.Subject) { SignedInAccounts = accounts };

        var client = await FindClientAsync(context, request.ClientId, cancellationToken).ConfigureAwait(false);
        return new LogoutRequest(new ClientInformation(request.ClientId, client?.DisplayName), request.Subject) { SignedInAccounts = accounts };
    }

    /// <summary>
    /// Returns the sign-out the page is asked to confirm, or <see langword="null"/> when there is
    /// none — for a page that renders its own "nothing to confirm" message.
    /// </summary>
    /// <remarks>
    /// Exactly <see cref="GetRequestAsync"/>, headers included, except that each case it reports with
    /// <see cref="ZeeKayDaInteractionException"/> returns <see langword="null"/>. A request with no
    /// <c>zkd_i</c> is logged as a warning.
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
    /// Signs out the account the sign-out is for, <see cref="LogoutRequest.Subject"/>, and sends the
    /// user on: to the client's registered post-logout redirect URI when the sign-out named one,
    /// carrying the client's <c>state</c>, and to the signed-out page otherwise. This is the Sign out
    /// button.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last thing
    /// the page does. A Razor Pages handler or controller action can simply end after it: the
    /// framework skips MVC's result. Anywhere else, returning a result of your own afterwards throws,
    /// because the response has started. Only a <c>POST</c> is accepted, checked before anything is
    /// read: wired to the <c>GET</c> that renders the page, it would sign the user out on arrival.
    /// </para>
    /// <para>
    /// That account's session ends, and so does every authorization request this browser has in
    /// flight. Any other account the browser is signed in to stays signed in;
    /// <see cref="SignOutAllAsync"/> ends them too. The redirect URI is checked against the client's
    /// registration as it stands now, so one the operator removed while the page was open is not used.
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
        await _nothingToContinue.SignOutStepAsync(context, () => ConfirmAsync(context, allAccounts: false)).ConfigureAwait(false);
    }

    /// <summary>
    /// Signs out every account this browser is signed in to, and sends the user on as
    /// <see cref="SignOutAsync"/> does. This is the "Sign out of all accounts" button, for a shared
    /// computer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Terminal</strong>, on the terms <see cref="SignOutAsync"/> states. Unlike it, this goes
    /// ahead when the account the sign-out was for has been signed out since, ending whatever
    /// accounts remain: it only ever removes access, and the sign-out's <c>zkd_i</c> binding still
    /// proves the request came from this browser's own page.
    /// </para>
    /// <para>
    /// The session cookie is removed, and every authorization request this browser has in flight
    /// ends. <see cref="LogoutRequest.SignedInAccounts"/> lists who that signs out.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be read. Fail-closed: nobody was signed out.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task SignOutAllAsync()
    {
        var context = RequireStateChangingRequest();
        await _nothingToContinue.SignOutStepAsync(context, () => ConfirmAsync(context, allAccounts: true)).ConfigureAwait(false);
    }

    private async Task ConfirmAsync(HttpContext context, bool allAccounts)
    {
        var request = await ResolveAddressedAsync(context, context.RequestAborted).ConfigureAwait(false);
        (SsoSessionList sessions, SsoSessionState? account) = allAccounts
            ? (await _session.ReadAsync(context).ConfigureAwait(false), null)
            : await RequireAskedSessionAsync(context, request, context.RequestAborted).ConfigureAwait(false);

        var client = request.ClientId is null
            ? null
            : await FindClientAsync(context, request.ClientId, context.RequestAborted).ConfigureAwait(false);
        var redirect = PostLogoutRedirect.For(client, request.PostLogoutRedirectUri, request.State);

        await _requests.DeleteAsync(context, request.Id, context.RequestAborted).ConfigureAwait(false);
        var result = account is null
            ? await _responses.EndAllAsync(context, sessions, redirect).ConfigureAwait(false)
            : await _responses.EndAccountAsync(context, sessions, account, redirect).ConfigureAwait(false);

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

        // Retires the binding's secret, which would otherwise hold a per-browser slot until it expires.
        await _requests.DeleteAsync(context, interactionId, cancellationToken).ConfigureAwait(false);

        throw new NothingToContinueException(
                NothingToContinueReason.NotFound,
                "There is no sign-out waiting to be confirmed with this identifier for this browser. It has " +
                "expired or already completed, the page was reached without going through the end-session " +
                "endpoint, or the sign-out was started in another browser.");
    }

    /// <summary>
    /// Refuses, and discards the sign-out, unless the browser still holds the account session it was
    /// started for: an answer about a session since ended is not an instruction about its replacement.
    /// </summary>
    private async ValueTask<(SsoSessionList Sessions, SsoSessionState Account)> RequireAskedSessionAsync(
        HttpContext context,
        LogoutRequestContext request,
        CancellationToken cancellationToken)
    {
        var sessions = await _session.ReadAsync(context).ConfigureAwait(false);
        var account = sessions.Accounts.FirstOrDefault(held =>
            string.Equals(held.SessionId, request.SsoSessionId, StringComparison.Ordinal)
            && string.Equals(held.Subject, request.Subject, StringComparison.Ordinal));

        if (account is not null)
            return (sessions, account);

        await _requests.DeleteAsync(context, request.Id, cancellationToken).ConfigureAwait(false);

        throw new NothingToContinueException(
            NothingToContinueReason.SessionChanged,
            "The session this sign-out was started for is not the one this browser holds now — it has " +
            "already ended, or the user signed in again since being asked. Start the sign-out again.");
    }

    /// <summary>
    /// The client's registration as it stands now, or <see langword="null"/> when it is no longer
    /// registered; from request services for the reason <c>AuthorizationFlow.ResolveClientAsync</c> gives.
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
                "that renders the page. Wire SignOutAsync and SignOutAllAsync to the form's post handlers.");
        }

        return context;
    }
}
