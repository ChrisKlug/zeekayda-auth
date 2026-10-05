using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host page's completion of an external sign-in that <c>ProviderSignInContext.RedirectToAsync</c>
/// parked: the collect-more page, or the account-linking page. One of the per-page interaction
/// services: the host owns the page and what it collects; this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page needs no scheme name and no cookie name — the framework redirected the user here and
/// knows which authorization request, and which parked principal, is being finished. The one
/// thing the page must preserve is the <c>zkd_i</c> query parameter it was reached with, which an
/// ordinary <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// A page that only collects what the provider did not supply passes the collected claims to
/// <see cref="SignInAsync"/>, and the framework builds the session principal the way it does when
/// no page is involved: the provider's claims under the derived subject, never the upstream one.
/// A page that links the external identity to a local account passes that account's own
/// principal to <see cref="SignInWithReplacedPrincipalAsync"/>.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — the request carries no <c>zkd_i</c>; the interaction expired, was
/// already completed or was started in another browser; no principal is parked for it any more; or another response completed it while
/// this one was being prepared — the framework answers the request itself. It sends the browser to
/// the client's registered <c>InitiateLoginUri</c>, with <c>iss</c>, to start again when the browser
/// can still say which client it came from, and to the error page with
/// <see cref="AuthorizationErrorKind.NothingToContinue"/> otherwise. The call is terminal either way.
/// A missing <c>zkd_i</c> is also logged as a warning, since a form that drops it causes the same
/// answer on every submission.
/// </para>
/// </remarks>
public sealed class ProviderSignInInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ProviderRegistry _providers;
    private readonly PageInteractionServices _services;

    internal ProviderSignInInteraction(
        IHttpContextAccessor httpContextAccessor,
        ProviderRegistry providers,
        PageInteractionServices services)
    {
        _httpContextAccessor = httpContextAccessor;
        _providers = providers;
        _services = services;
    }

    private const string Page = "provider sign-in";

    /// <summary>
    /// The principal the external provider authenticated, parked for the interaction this request
    /// is addressed to, or <see langword="null"/> when there is none: the redirect did not come
    /// from <c>RedirectToAsync</c>, the parked principal has expired, or it belongs to another
    /// interaction, or the request carries no <c>zkd_i</c> at all. A page that gets
    /// <see langword="null"/> has nothing to finish and should say so, not fail. A missing
    /// <c>zkd_i</c> is also logged as a warning, since a form that drops it looks the same.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// The page shows the provider's identity and takes a one-click decision, so the response
    /// this is called from is marked unframeable (<c>Content-Security-Policy: frame-ancestors
    /// 'none'</c>, appended alongside any policy of the host's, and <c>X-Frame-Options: DENY</c>)
    /// and uncacheable (<c>Cache-Control: no-store</c>), as the consent page's is — whatever the
    /// read finds. A page renders nothing meaningful without this call, so every rendered page
    /// carries the protection; one that renders without calling it is on its own.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: a parked principal that cannot be
    /// read is not reported as absent, since the page would then tell the user there is nothing
    /// to finish.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    public async Task<PendingPrincipal?> GetPendingPrincipalAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();

        // Stamped whatever the read finds: the page renders either way, and the one that shows the
        // provider's identity and takes a decision is the one an attacker would frame.
        RenderedPage.Protect(context.Response);

        if (await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false) is not { } interactionId)
        {
            _services.NothingToContinue.Log(Page, NothingToContinueReason.NoInteractionId);
            return null;
        }

        var pending = await _services.Flow.ReadPendingAsync(context, interactionId, cancellationToken).ConfigureAwait(false);
        if (pending is null || _providers.Find(pending.Provider) is not { } registration)
            return null;

        return new PendingPrincipal(pending.Principal, registration.Descriptor);
    }

    /// <summary>
    /// Establishes the SSO session for the parked principal, with <paramref name="additionalClaims"/>
    /// added, and continues the authorization request that led here.
    /// </summary>
    /// <param name="additionalClaims">
    /// What the page collected, added alongside the provider's claims — only the additions, not
    /// the provider's claims over again. The subject is the framework's: a <c>sub</c> or
    /// <see cref="ClaimTypes.NameIdentifier"/> claim is refused, and claims in the reserved
    /// <c>zkd:</c> namespace are stripped. Pass none to promote the parked principal as it is.
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
    /// The session holds what an external sign-in with no page involved would hold: the
    /// provider's claims under a subject derived from the provider, the subject claim's issuer
    /// and the upstream subject together, plus what was collected. No <c>amr</c> is reported,
    /// since the framework was told nothing about how the user proved who they are at the
    /// provider. The parked principal is consumed.
    /// </para>
    /// <para>
    /// Every refusal of the sign-in itself is decided before the parked principal is taken, so
    /// a refused page can try again, or send the user back to the login page, with the principal
    /// still parked. Two things are found later: another response completing the interaction
    /// first, and a principal parked by a second provider return while this sign-in was in flight,
    /// which is promoted in place of the one read and, if it cannot be, is gone with the refusal.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The parked principal cannot be promoted: its provider is no longer registered, it carries no
    /// subject on an authenticated identity, or its subject claim names no issuer — a provider
    /// handler that must be fixed, since it fails every time.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached before the
    /// session was established. Fail-closed: nothing was signed in or issued. A store fault
    /// after that point is answered to the client as <c>server_error</c> rather than thrown,
    /// with the session already established.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="additionalClaims"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="additionalClaims"/> is null, or names the subject.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c> — only the form's submission may sign in, and that is
    /// checked before anything is read — or there is no active HTTP request.
    /// </exception>
    public async Task SignInAsync(params Claim[] additionalClaims)
    {
        ArgumentNullException.ThrowIfNull(additionalClaims);

        // A snapshot of the caller's array: what is validated is what is promoted, however the
        // caller's copy changes while the store is awaited. The subject is refused rather than
        // dropped: a page passing one expects it to be used, and silently replacing it would
        // hide the mistake this service exists to prevent.
        var collected = additionalClaims.ToArray();
        if (collected.Any(claim => claim is null))
            throw new ArgumentException("An entry in the additional claims is null.", nameof(additionalClaims));

        if (collected.Any(claim => ExternalSubject.IsSubjectClaimType(claim.Type)))
        {
            throw new ArgumentException(
                "An additional claim names the subject. The session subject of an external sign-in is " +
                "derived by the framework from the provider, the issuer and the upstream subject; a " +
                "page that links the external identity to a local account passes that account's " +
                "principal to SignInWithReplacedPrincipalAsync instead.",
                nameof(additionalClaims));
        }

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, () => SignInWithParkedAsync(context, collected)).ConfigureAwait(false);
    }

    private async Task SignInWithParkedAsync(HttpContext context, Claim[] additionalClaims)
    {
        var (requestContext, parked) = await ResolveParkedAsync(context).ConfigureAwait(false);

        // Validated on the parked principal before it is taken, so a principal that cannot be
        // promoted stays where it is; built again from what was taken, so nothing stale is promoted.
        Promote(parked);
        var taken = await TakeParkedAsync(context, requestContext).ConfigureAwait(false);
        var promoted = Promote(taken);
        ((ClaimsIdentity)promoted.Identity!).AddClaims(additionalClaims.Where(claim => !ReservedClaims.IsReserved(claim)));

        // Nothing is stated about how the user proved who they are at the provider, as for an
        // external sign-in that involved no page.
        await _services.Outcomes.CompleteSignInAsync(context, requestContext, new SignIn(promoted, AuthenticationMethods: [], taken.Provider))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Establishes the SSO session for <paramref name="principal"/> in place of the parked one —
    /// a local account the page linked the external identity to — and continues the authorization
    /// request that led here.
    /// </summary>
    /// <param name="principal">
    /// The account the session is for, replacing the parked principal entirely: nothing the
    /// provider returned is carried into the session. Must carry a <c>sub</c> or
    /// <see cref="ClaimTypes.NameIdentifier"/> claim; that subject must not be the upstream one
    /// the provider returned, and claims in the framework's reserved <c>zkd:</c> namespace are
    /// stripped.
    /// </param>
    /// <param name="authenticationMethods">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values, or pass your own string for
    /// a method the registry does not name. Passing none omits the claim.
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
    /// Linking can be more involved than adding a claim — matching an existing account, creating
    /// one, asking the user to sign in locally first — so the session holds the principal the
    /// page built, subject included, exactly as the login page's sign-in does. The parked
    /// principal is consumed, and the provider that parked it is recorded on the request. What
    /// it is not for is passing the parked principal back: the session subject of an external
    /// sign-in is never the upstream subject verbatim, and a replacement carrying it is refused.
    /// </para>
    /// <para>
    /// Every refusal of the sign-in itself is decided before the parked principal is taken, so
    /// a refused page can try again with the principal still parked. Two things are found later:
    /// another response completing the interaction first, and a principal parked by a second
    /// provider return while this sign-in was in flight, which is held to the same subject rule
    /// and, when refused, is gone with the refusal.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The parked principal's provider is no longer registered. Or <paramref name="principal"/>
    /// carries no subject, or its subject is the upstream subject the provider returned.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached before the
    /// session was established. Fail-closed: nothing was signed in or issued. A store fault
    /// after that point is answered to the client as <c>server_error</c> rather than thrown,
    /// with the session already established.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="principal"/> or <paramref name="authenticationMethods"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="authenticationMethods"/> is null or blank.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    public async Task SignInWithReplacedPrincipalAsync(ClaimsPrincipal principal, params string[] authenticationMethods)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        var methods = authenticationMethods.ToArray();
        if (methods.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "An authentication method reference is null or blank. Pass a value such as "
                + "AuthenticationMethods.Password, or pass none to omit the amr claim.",
                nameof(authenticationMethods));

        // A snapshot, rebuilt on the framework's own identity type: what is validated is what is
        // promoted, whatever the page does to its principal afterwards. Checked before the parked
        // principal is taken: a principal the session would refuse must not cost the page the one
        // thing it needs to try again.
        var replacement = ReservedClaims.Snapshot(principal);
        if (!HasSubject(replacement))
        {
            throw new ZeeKayDaInteractionException(
                "The principal passed to SignInWithReplacedPrincipalAsync carries no subject. Add a 'sub' or " +
                $"'{ClaimTypes.NameIdentifier}' claim identifying the user.");
        }

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, () => SignInAsReplacementAsync(context, replacement, methods)).ConfigureAwait(false);
    }

    private async Task SignInAsReplacementAsync(HttpContext context, ClaimsPrincipal replacement, string[] methods)
    {
        var (requestContext, parked) = await ResolveParkedAsync(context).ConfigureAwait(false);

        RequireRegistered(parked);
        if (CarriesUpstreamSubject(replacement, parked.Principal))
            throw UpstreamSubjectRefused();

        // Checked again on what was taken: a principal parked between the read and the take is
        // held to the same rule, at the cost of losing it — the concurrent re-park is the one
        // path on which a refusal costs the page its retry.
        var taken = await TakeParkedAsync(context, requestContext).ConfigureAwait(false);
        RequireRegistered(taken);
        if (CarriesUpstreamSubject(replacement, taken.Principal))
            throw UpstreamSubjectRefused();

        await _services.Outcomes.CompleteSignInAsync(context, requestContext, new SignIn(replacement, methods, taken.Provider))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Cancel button of the
    /// page, and a linking page's refusal.
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
    /// No SSO session is established, and an existing one is left alone. The interaction and the
    /// principal parked for it are discarded, so the request cannot afterwards be resumed. The
    /// client receives the same refusal <c>ProviderSignInContext.DenyAsync</c> sends — an
    /// <c>error_description</c> naming a refusal after sign-in at the external provider and, for a
    /// client registered with <c>EnableZkdErrorCodes</c>, the <c>zkd_error</c> <c>account_refused</c>.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A cancel wired to a <c>GET</c> anchor would be triggerable cross-site by
    /// anyone who learned the interaction identifier.
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
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    public async Task DenyAsync()
    {
        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);
            await _services.Outcomes.DenyAsync(context, requestContext, Denial.RefusedAfterProvider).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// The interaction the request is addressed to and the principal parked for it, read but not
    /// taken. A sign-in from this page finishes an external sign-in, so an interaction with
    /// nothing parked is refused before anything is promoted — the login page is where a sign-in
    /// from nothing belongs.
    /// </summary>
    private async Task<(AuthorizationRequestContext RequestContext, PendingTicket Parked)> ResolveParkedAsync(HttpContext context)
    {
        var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        var parked = await _services.Flow.ReadPendingAsync(context, requestContext.Id, context.RequestAborted).ConfigureAwait(false)
            ?? throw NothingParked();

        return (requestContext, parked);
    }

    /// <summary>
    /// Takes the parked principal out of the store: what is promoted is what was taken, so a
    /// principal parked between the read and the take is promoted rather than discarded, and one
    /// taken by another post in the meantime refuses this one. Two posts that both take the same
    /// principal both promote the same person; the completion claim decides which one issues.
    /// </summary>
    private async Task<PendingTicket> TakeParkedAsync(HttpContext context, AuthorizationRequestContext requestContext) =>
        await _services.Flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false)
        ?? throw NothingParked();

    private static ZeeKayDaInteractionException UpstreamSubjectRefused() => new(
        "The replacement principal's subject is the upstream subject the provider returned. The " +
        "session subject of an external sign-in is never the upstream one verbatim: pass a local " +
        "account's own principal, or let SignInAsync derive the subject.");

    private static NothingToContinueException NothingParked() => new(
        NothingToContinueReason.NothingParked,
        "No external sign-in is parked for this interaction: it expired, was already used, or the " +
        "user did not arrive here through RedirectToAsync. Send the user back to the login page.");

    /// <summary>The principal to promote for a parked ticket, from a provider still registered.</summary>
    private ClaimsPrincipal Promote(PendingTicket ticket)
    {
        RequireRegistered(ticket);
        return ExternalSubject.ForPromotion(ticket.Provider, ticket.Principal);
    }

    /// <summary>
    /// A parked principal from a provider that has since been removed from the registration is
    /// refused, as <see cref="GetPendingPrincipalAsync"/> reports none: what the host no longer
    /// trusts to sign users in does not get to finish a sign-in it started.
    /// </summary>
    private void RequireRegistered(PendingTicket ticket)
    {
        if (_providers.Find(ticket.Provider) is null)
        {
            throw new ZeeKayDaInteractionException(
                "The provider that authenticated the parked principal is no longer registered, so the " +
                "sign-in cannot be finished. Send the user back to the login page.");
        }
    }

    /// <summary>
    /// Selected as the session selects it — the first claim of each type, in order — so a
    /// principal that passes here is one the session will accept after the take.
    /// </summary>
    private static bool HasSubject(ClaimsPrincipal principal) =>
        ExternalSubject.SubjectClaimTypes.Any(type => !string.IsNullOrEmpty(principal.FindFirstValue(type)));

    /// <summary>
    /// Whether the replacement names, as its subject, a subject the provider returned — the
    /// literal pass-through of the parked principal, or a copy of its subject claim. Compared by
    /// value: a host keying local accounts by the upstream subject verbatim is the very thing
    /// the derived subject exists to prevent.
    /// </summary>
    private static bool CarriesUpstreamSubject(ClaimsPrincipal replacement, ClaimsPrincipal parked) =>
        SubjectValues(replacement).Intersect(SubjectValues(parked), StringComparer.Ordinal).Any();

    private static IEnumerable<string> SubjectValues(ClaimsPrincipal principal) =>
        principal.Claims
            .Where(claim => ExternalSubject.IsSubjectClaimType(claim.Type) && !string.IsNullOrEmpty(claim.Value))
            .Select(claim => claim.Value);

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "ProviderSignInInteraction requires an active HTTP request. Resolve it from request " +
            "services inside the page, not from a background service.");

    /// <summary>
    /// A terminal step is taken only from a form post. The framework arrives at the page with a
    /// GET, and the framework's cookies accompany a top-level GET from anywhere, so a sign-in or a
    /// cancel wired to a link would be triggerable by a page that never showed the user anything.
    /// Checked before any state is read, so a wrongly wired page changes nothing.
    /// </summary>
    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "A sign-in or cancellation must come from a POST — the page's form submission — not " +
                "from the request that renders the page. Wire SignInAsync, SignInWithReplacedPrincipalAsync " +
                "and DenyAsync to the form's post handlers.");
        }

        return context;
    }
}
