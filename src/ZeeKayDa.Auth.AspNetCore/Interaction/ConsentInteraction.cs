using System.Collections.Immutable;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host consent page's completion of an authorization request. One of the per-page
/// interaction services: the host owns the page and its wording; this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The framework redirects the user here after sign-in when the client requires consent, at the
/// configured <c>AuthorizationEndpoint.Interaction.ConsentPath</c>. As with the login page, the
/// one thing the page must preserve is the <c>zkd_i</c> query parameter it was reached with,
/// which an ordinary <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// Every method is bound to the interaction the request is addressed to <em>and</em> to the
/// session that was authenticated for it: a consent decision is recorded by the user it was
/// asked of, never by whoever holds the browser afterwards.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — the request carries no <c>zkd_i</c>; the interaction expired, was
/// already completed or was started in another browser; the session that authenticated it is no longer the one the browser holds; the client
/// is no longer registered; or another response completed it while
/// this one was being prepared — the framework answers the request itself. It sends the browser to
/// the client's registered <c>InitiateLoginUri</c>, with <c>iss</c>, to start again when the browser
/// can still say which client it came from, and to the error page with
/// <see cref="AuthorizationErrorKind.NothingToContinue"/> otherwise. The call is terminal either way.
/// A missing <c>zkd_i</c> is also logged as a warning, since a form that drops it causes the same
/// answer on every submission.
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

    /// <summary>
    /// What a declined request tells the client. Names the stage, as the sign-in cancellation
    /// does, so the two read differently on the wire; generic by construction, echoing no value.
    /// </summary>
    private const string DeclinedAtConsent = "The user declined the request at the consent page.";

    /// <summary>
    /// What a grant without <c>openid</c> tells the client: consent to be identified was
    /// withheld, which is the whole of what an OpenID Connect request asks for.
    /// </summary>
    private const string IdentityWithheld = "The user did not consent to being identified to the client.";

    private const string Page = "consent";

    /// <summary>
    /// What the page should ask: the client, the scopes it wants, and who is being asked.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// The page takes a one-click decision, so the response this is called from is marked
    /// unframeable (<c>Content-Security-Policy: frame-ancestors 'none'</c>, appended alongside
    /// any policy of the host's, and <c>X-Frame-Options: DENY</c>) and uncacheable
    /// (<c>Cache-Control: no-store</c>). A page renders nothing meaningful without this call, so
    /// every rendered consent page carries the protection; one that renders without calling it is
    /// on its own.
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

        // Stamped before the read, so whatever the page renders — the question, or its own
        // "nothing to ask" after TryGetRequestAsync — is framed by nobody and cached by nothing.
        RenderedPage.Protect(context.Response);
        var (requestContext, client) = await ResolveAsync(context, cancellationToken).ConfigureAwait(false);

        // The subject was written by the same promotion that wrote the session identifier
        // ResolveAsync just matched, so it is present whenever that check passed.
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
    /// Exactly <see cref="GetRequestAsync"/>, including the headers it stamps, except that each case
    /// <see cref="GetRequestAsync"/> reports with <see cref="ZeeKayDaInteractionException"/> returns
    /// <see langword="null"/> instead. A request with no <c>zkd_i</c> is logged as a warning, since
    /// a form that drops it looks like this on every submission.
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
    /// <see cref="ConsentRequest.Scopes"/> count; anything else is dropped without comment, so
    /// a page cannot widen what was asked.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. A Razor Pages handler or controller action can simply end after it:
    /// the framework skips MVC's result, including one the handler returns. Anywhere else,
    /// returning a result of your own after calling it throws, because the response has already
    /// started.
    /// </para>
    /// <para>
    /// A grant that leaves out <c>openid</c> is a refusal to be identified to the client, and is
    /// answered as one: the client receives <c>access_denied</c>, as from <see cref="DenyAsync"/>.
    /// A page that does not want to offer that choice renders <c>openid</c> as required.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the consent form's submission — is accepted, and that is checked
    /// before anything is read. The framework arrives at the page with a <c>GET</c>, so a page
    /// that decided in its render handler would grant every request on arrival.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
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

        // Materialised and checked before anything is resolved, so a bad argument is blamed on
        // the caller's argument rather than surfacing as a mangled grant.
        var answered = scopes.ToArray();
        if (answered.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("An entry in scopes is null or blank.", nameof(scopes));

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, () => DecideAsync(context, answered)).ConfigureAwait(false);
    }

    private async Task DecideAsync(HttpContext context, string[] answered)
    {
        var (requestContext, client) = await ResolveAsync(context, context.RequestAborted).ConfigureAwait(false);

        // The page's answer can only narrow what was asked: intersected in request order, over
        // ordinal comparison, so a page cannot grant a scope the request never carried.
        var granted = requestContext.Scopes
            .Where(scope => answered.Contains(scope, StringComparer.Ordinal))
            .ToImmutableArray();

        if (!granted.Contains(StandardScopes.OpenId.Name, StringComparer.Ordinal))
        {
            await _services.Outcomes.DenyAsync(context, requestContext, IdentityWithheld).ConfigureAwait(false);
            return;
        }

        await _services.Outcomes.CompleteConsentAsync(context, requestContext, client, granted).ConfigureAwait(false);
    }

    /// <summary>
    /// Ends the authorization request without consent, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Deny button.
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
    /// The SSO session is left alone — declining one client does not sign the user out of
    /// another. The interaction is discarded, so the declined request cannot afterwards be
    /// resumed. The client receives an <c>error_description</c> stating that the user declined
    /// at the consent page, so it can tell this apart from the other refusals that also answer
    /// <c>access_denied</c>.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A deny reachable by a link could be triggered cross-site by anyone who
    /// learned the interaction identifier, ending the user's in-flight request.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
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
            await _services.Outcomes.DenyAsync(context, requestContext, DeclinedAtConsent).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// The interaction this request may decide consent for, and the client it is for: addressed
    /// by <c>zkd_i</c> on the login service's exact terms, authenticated by the session this
    /// browser still holds, and sent by a client that is still registered.
    /// </summary>
    /// <remarks>
    /// The registration is read again here rather than remembered from the handoff. A client
    /// removed or invalidated since then, or one that no longer lists the request's redirect URI,
    /// has no page worth rendering and no redirect URI anyone vouches for any more, so the
    /// request ends where it stands.
    /// </remarks>
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

    /// <summary>
    /// A decision is taken only from a form post. The framework itself arrives at the consent
    /// page with a GET, so a page whose GET handler decided would grant every request the moment
    /// the user landed on it — with no user action, which is the very thing consent exists to
    /// require. Checked before any state is read, so a wrongly wired page changes nothing.
    /// </summary>
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
