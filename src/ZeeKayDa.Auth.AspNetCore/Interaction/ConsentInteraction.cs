using System.Collections.Immutable;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host consent page's completion of an authorization request, at
/// <c>AuthorizationEndpoint.Interaction.ConsentPath</c>. The host owns the page and its wording;
/// this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page must preserve the <c>zkd_i</c> query parameter it was reached with, which an ordinary
/// <c>&lt;form method="post"&gt;</c> does by default. Every method is bound to that interaction
/// <em>and</em> to the session authenticated for it, so a decision is recorded by the user it was
/// asked of, never by whoever holds the browser afterwards.
/// </para>
/// <para>
/// <strong>Terminal methods</strong> — <see cref="GrantAsync"/> and <see cref="DenyAsync"/> — write
/// and commit the response, so each must be the last thing the page does. A Razor Pages handler or
/// controller action can simply end after it: the framework skips MVC's result. Anywhere else,
/// returning a result of your own afterwards throws, because the response has started. Only a
/// <c>POST</c> is accepted, checked before anything is read: the framework arrives at the page with
/// a <c>GET</c>, so a page deciding in its render handler would grant every request on arrival.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — no <c>zkd_i</c>; the interaction expired, was completed or belongs
/// to another browser; the session that authenticated it has changed; the client is no longer
/// registered; or another response completed it first — the framework sends the browser to the
/// client's <c>InitiateLoginUri</c>, with <c>iss</c>, when it can still say which client it came
/// from, and to the error page with <see cref="AuthorizationErrorKind.NothingToContinue"/>
/// otherwise. A missing <c>zkd_i</c> is also logged as a warning, since a form that drops it fails
/// on every submission.
/// </para>
/// </remarks>
public sealed class ConsentInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly PageInteractionServices _services;

    internal ConsentInteraction(
        IHttpContextAccessor httpContextAccessor,
        PageInteractionServices services)
    {
        _httpContextAccessor = httpContextAccessor;
        _services = services;
    }

    private const string Page = "consent";

    /// <summary>
    /// What the page should ask: the client, the scopes it wants, and who is being asked.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// The page takes a one-click decision, so the response is marked unframeable
    /// (<c>Content-Security-Policy: frame-ancestors 'none'</c>, appended to any policy of the host's,
    /// and <c>X-Frame-Options: DENY</c>) and <c>Cache-Control: no-store</c>, before the read. A page
    /// that renders without calling this is on its own.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to ask about: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, or was started
    /// in another browser; or the session that authenticated the request is no longer the one the
    /// browser holds; or the client that sent the request is no longer registered or no longer
    /// lists its redirect URI. A page that wants to render its own message for these cases calls
    /// <see cref="TryGetRequestAsync"/> instead.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: nothing is reported as absent.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    public async Task<ConsentRequest> GetRequestAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();

        cancellationToken.ThrowIfCancellationRequested();

        RenderedPage.Protect(context.Response);
        var (requestContext, client) = await ResolveAsync(context, cancellationToken).ConfigureAwait(false);

        // Written with the session identifier ResolveAsync just matched.
        return new ConsentRequest(
            new ClientInformation(requestContext.ClientId, client.DisplayName),
            requestContext.Scopes.ToImmutableArray(),
            requestContext.Subject!);
    }

    /// <summary>
    /// What the page should ask, or <see langword="null"/> when there is nothing to ask about — for
    /// a page that renders its own "nothing to continue" message.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// Exactly <see cref="GetRequestAsync"/>, headers included, except that each case it reports with
    /// <see cref="ZeeKayDaInteractionException"/> returns <see langword="null"/>. A request with no
    /// <c>zkd_i</c> is logged as a warning.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: nothing is reported as absent.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    public async Task<ConsentRequest?> TryGetRequestAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await GetRequestAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (NothingToContinueException missing)
        {
            _services.NothingToContinue.Log(Page, missing);
            return null;
        }
    }

    /// <summary>
    /// Records the user's consent to <paramref name="scopes"/> and continues the authorization
    /// request.
    /// </summary>
    /// <param name="scopes">
    /// The scopes the user agreed to, typically the boxes they ticked. Only entries in
    /// <see cref="ConsentRequest.Scopes"/> count; anything else is dropped without comment, so a
    /// page cannot widen what was asked.
    /// </param>
    /// <remarks>
    /// Terminal (see the class remarks). A grant always includes <c>openid</c>: agreeing to anything
    /// is agreeing to be identified to the client, so an empty grant grants <c>openid</c> alone. A
    /// page that wants to refuse calls <see cref="DenyAsync"/>.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was issued.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="scopes"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="scopes"/> is null or blank.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task GrantAsync(IEnumerable<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        var answered = scopes.ToArray();
        if (answered.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("An entry in scopes is null or blank.", nameof(scopes));

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, () => DecideAsync(context, answered)).ConfigureAwait(false);
    }

    private async Task DecideAsync(HttpContext context, string[] answered)
    {
        var (requestContext, client) = await ResolveAsync(context, context.RequestAborted).ConfigureAwait(false);
        var granted = NarrowToRequested(requestContext.Scopes, answered);

        await _services.Outcomes.CompleteConsentAsync(context, requestContext, client, granted).ConfigureAwait(false);
    }

    /// <summary>The requested scopes the page's answer names, in request order, and always <c>openid</c>.</summary>
    private static ImmutableArray<string> NarrowToRequested(IEnumerable<string> requested, string[] answered) =>
        requested
            .Where(scope => scope == StandardScopes.OpenId.Name || answered.Contains(scope, StringComparer.Ordinal))
            .ToImmutableArray();

    /// <summary>
    /// Ends the authorization request without consent, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Deny button.
    /// </summary>
    /// <remarks>
    /// Terminal (see the class remarks). The SSO session is left alone: declining one client does not
    /// sign the user out of another. The interaction is discarded. A client registered with
    /// <c>EnableZkdErrorCodes</c> also receives the <c>zkd_error</c> <c>consent_declined</c>, to tell
    /// this apart from other <c>access_denied</c> refusals.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// the client was told nothing.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task DenyAsync()
    {
        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var (requestContext, _) = await ResolveAsync(context, context.RequestAborted).ConfigureAwait(false);
            await _services.Outcomes.DenyAsync(context, requestContext, Denial.DeclinedAtConsent).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// The addressed interaction, if the session this browser holds authenticated it, and its client,
    /// read again so that one removed since the handoff, or no longer listing the redirect URI, ends it.
    /// </summary>
    private async ValueTask<(AuthorizationRequestContext RequestContext, IClient Client)> ResolveAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        if (!await _services.Flow.IsAuthenticatedByCurrentSessionAsync(context, requestContext).ConfigureAwait(false))
        {
            throw new NothingToContinueException(
                NothingToContinueReason.SessionChanged,
                "The session that authenticated this authorization request is not the one this browser " +
                "holds: the user signed out, or signed in again as someone else, before answering the " +
                "consent page. Start the authorization request again.");
        }

        var client = await _services.Flow.ResolveClientAsync(context, requestContext, cancellationToken).ConfigureAwait(false)
            ?? throw new NothingToContinueException(
                NothingToContinueReason.ClientGone,
                "The client that sent this authorization request is no longer registered, or no longer " +
                "lists its redirect URI, so there is nothing to consent to. Start the authorization " +
                "request again.");

        return (requestContext, client);
    }

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "ConsentInteraction requires an active HTTP request. Resolve it from request services " +
            "inside the consent page, not from a background service.");

    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "A consent decision must come from a POST — the consent form's submission — not from the " +
                "request that renders the page. Wire GrantAsync and DenyAsync to the form's post handler.");
        }

        return context;
    }
}
