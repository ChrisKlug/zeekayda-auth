using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host page's completion of an external sign-in that <c>ProviderSignInContext.RedirectToAsync</c>
/// parked: the collect-more page, or the account-linking page. The host owns the page; this service
/// owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page must preserve the <c>zkd_i</c> query parameter it was reached with, which an ordinary
/// <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// A page that collects what the provider did not supply calls <see cref="SignInAsync"/>, and the
/// session holds the provider's claims under the derived subject, never the upstream one. A page
/// that links the external identity to a local account calls
/// <see cref="SignInWithReplacedAccountAsync(string, IEnumerable{string}, Claim[])"/>.
/// </para>
/// <para>
/// <strong>Terminal methods</strong> — every one but <see cref="GetPendingPrincipalAsync"/> — write
/// and commit the response, so each must be the last thing the page does. A Razor Pages handler or
/// controller action can simply end after it: the framework skips MVC's result. Anywhere else,
/// returning a result of your own afterwards throws, because the response has started. Only a
/// <c>POST</c> is accepted, checked before anything is read: the framework's cookies accompany a
/// cross-site top-level <c>GET</c>, so a step wired to a link could be triggered unseen.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — no <c>zkd_i</c>; the interaction expired, was completed or belongs
/// to another browser; nothing is parked for it; or another response completed it first — the
/// framework sends the browser to the client's <c>InitiateLoginUri</c>, with <c>iss</c>, when it can
/// still say which client it came from, and to the error page with
/// <see cref="AuthorizationErrorKind.NothingToContinue"/> otherwise. A missing <c>zkd_i</c> is also
/// logged as a warning, since a form that drops it fails on every submission.
/// </para>
/// <para>
/// Every refusal of a sign-in is decided before the parked principal is taken, so a refused page
/// can try again with it still parked. The exception is a principal parked by a second provider
/// return while the sign-in was in flight: it is held to the same rules, and is gone if refused.
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
    /// is addressed to, or <see langword="null"/> when there is none — it expired, belongs to
    /// another interaction, or the request carries no <c>zkd_i</c>. A page that gets
    /// <see langword="null"/> has nothing to finish and should say so, not fail.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// Whatever the read finds, the response is marked unframeable (<c>Content-Security-Policy:
    /// frame-ancestors 'none'</c>, appended to any policy of the host's, and <c>X-Frame-Options:
    /// DENY</c>) and <c>Cache-Control: no-store</c>: the page shows the provider's identity and takes
    /// a one-click decision. A page that renders without calling this is on its own.
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

        RenderedPage.Protect(context.Response);

        if (await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false) is not { } interactionId)
        {
            _services.NothingToContinue.Log(Page, NothingToContinueReason.NoInteractionId);
            return null;
        }

        var pending = await _services.Flow.ReadPendingAsync(context, interactionId, cancellationToken).ConfigureAwait(false);
        if (pending is null || _providers.Find(pending.Provider) is not { } registration)
            return null;

        return new PendingPrincipal(
            ExternalSubject.Identify(registration.Name, pending.Principal), pending.Principal, registration.Descriptor);
    }

    /// <summary>
    /// Establishes the SSO session for the parked principal, with <paramref name="additionalClaims"/>
    /// added, and continues the authorization request that led here.
    /// </summary>
    /// <param name="additionalClaims">
    /// What the page collected, added to the provider's claims; pass none to promote the parked
    /// principal as it is. Held on the SSO session only: tokens and userinfo get their claims from
    /// <c>IClaimsProvider</c>. A <c>sub</c> or <see cref="ClaimTypes.NameIdentifier"/> claim is
    /// refused, and claims in the reserved <c>zkd:</c> namespace are stripped.
    /// </param>
    /// <remarks>
    /// Terminal (see the class remarks). The session holds what an external sign-in with no page
    /// would hold — the provider's claims under the derived subject — plus what was collected. No
    /// <c>amr</c> is reported: the framework was told nothing about how the user proved who they
    /// are at the provider.
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
        var collected = SessionPrincipal.AdditionalClaims(additionalClaims);

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, () => SignInWithParkedAsync(context, collected)).ConfigureAwait(false);
    }

    private async Task SignInWithParkedAsync(HttpContext context, Claim[] additionalClaims)
    {
        var (requestContext, parked) = await ResolveParkedAsync(context).ConfigureAwait(false);

        RequirePromotable(parked);
        var taken = await TakeParkedAsync(context, requestContext).ConfigureAwait(false);
        var promoted = Promote(taken);
        ((ClaimsIdentity)promoted.Identity!).AddClaims(additionalClaims);

        await _services.Outcomes.CompleteSignInAsync(context, requestContext, new SignIn(promoted, AuthenticationMethods: [], taken.Provider))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Establishes the SSO session for <paramref name="subject"/>, a local account, in place of
    /// the parked principal, and continues the authorization request that led here.
    /// </summary>
    /// <param name="subject">
    /// The local account the session is for. It must not be the upstream subject the provider
    /// returned.
    /// </param>
    /// <param name="authenticationMethod">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values, or pass your own string for
    /// a method the registry does not name. A sign-in that used several takes the overload with a
    /// list.
    /// </param>
    /// <param name="additionalClaims">
    /// Claims held on the SSO session alongside the subject, on the same terms as the overload
    /// taking a list of methods.
    /// </param>
    /// <remarks>
    /// Exactly the overload taking a list of methods, with one method in it.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The parked principal's provider is no longer registered, or <paramref name="subject"/> is
    /// the upstream subject the provider returned.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached before the
    /// session was established. Fail-closed: nothing was signed in or issued. A store fault
    /// after that point is answered to the client as <c>server_error</c> rather than thrown,
    /// with the session already established.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="additionalClaims"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> or <paramref name="authenticationMethod"/> is null or blank, or
    /// an entry in <paramref name="additionalClaims"/> is null or names the subject.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    public Task SignInWithReplacedAccountAsync(string subject, string authenticationMethod, params Claim[] additionalClaims)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationMethod);

        return SignInWithReplacedAccountAsync(subject, [authenticationMethod], additionalClaims);
    }

    /// <summary>
    /// Establishes the SSO session for <paramref name="subject"/>, a local account, in place of
    /// the parked principal, and continues the authorization request that led here.
    /// </summary>
    /// <param name="subject">
    /// The local account the session is for. It must not be the upstream subject the provider
    /// returned.
    /// </param>
    /// <param name="authenticationMethods">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values, or pass your own string for
    /// a method the registry does not name. An empty list omits the claim.
    /// </param>
    /// <param name="additionalClaims">
    /// Claims held on the SSO session alongside the subject. Held on the session only: tokens and
    /// userinfo get their claims from <c>IClaimsProvider</c>. A <c>sub</c> or
    /// <see cref="ClaimTypes.NameIdentifier"/> claim is refused, and claims in the reserved
    /// <c>zkd:</c> namespace are stripped.
    /// </param>
    /// <remarks>
    /// Terminal (see the class remarks). This is account linking: the page decided the external
    /// identity belongs to one of the host's own accounts, and nothing the provider returned is
    /// carried into the session. The upstream subject is refused as <paramref name="subject"/>: an
    /// external sign-in's session subject is never the upstream one verbatim. The arguments are
    /// copied when the call is made, so what was validated is what is signed in.
    /// <para>
    /// Find the local account by <see cref="PendingPrincipal.Identity"/>, never by an unverified
    /// email: see <see cref="ExternalIdentity"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The parked principal's provider is no longer registered, or <paramref name="subject"/> is
    /// the upstream subject the provider returned.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached before the
    /// session was established. Fail-closed: nothing was signed in or issued. A store fault
    /// after that point is answered to the client as <c>server_error</c> rather than thrown,
    /// with the session already established.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="authenticationMethods"/> or <paramref name="additionalClaims"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> or an entry in <paramref name="authenticationMethods"/> is null
    /// or blank, or an entry in <paramref name="additionalClaims"/> is null or names the subject.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    public async Task SignInWithReplacedAccountAsync(string subject, IEnumerable<string> authenticationMethods, params Claim[] additionalClaims)
    {
        var methods = SessionPrincipal.Methods(authenticationMethods);
        var replacement = SessionPrincipal.Build(subject, additionalClaims);

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, () => SignInAsReplacementAsync(context, replacement, methods)).ConfigureAwait(false);
    }

    private async Task SignInAsReplacementAsync(HttpContext context, ClaimsPrincipal replacement, string[] methods)
    {
        var (requestContext, parked) = await ResolveParkedAsync(context).ConfigureAwait(false);

        RequireReplaceable(parked, replacement);
        var taken = await TakeParkedAsync(context, requestContext).ConfigureAwait(false);
        RequireReplaceable(taken, replacement);

        await _services.Outcomes.CompleteSignInAsync(context, requestContext, new SignIn(replacement, methods, taken.Provider))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Cancel button of the
    /// page, and a linking page's refusal.
    /// </summary>
    /// <remarks>
    /// Terminal (see the class remarks). No SSO session is established, and an existing one is left
    /// alone. The interaction and its parked principal are discarded. The client receives the same
    /// refusal <c>ProviderSignInContext.DenyAsync</c> sends, including, for a client registered with
    /// <c>EnableZkdErrorCodes</c>, the <c>zkd_error</c> <c>account_refused</c>.
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
    /// The addressed interaction and the principal parked for it, read but not taken. Nothing parked
    /// is refused: a sign-in from nothing belongs on the login page.
    /// </summary>
    private async Task<(AuthorizationRequestContext RequestContext, PendingTicket Parked)> ResolveParkedAsync(HttpContext context)
    {
        var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        var parked = await _services.Flow.ReadPendingAsync(context, requestContext.Id, context.RequestAborted).ConfigureAwait(false)
            ?? throw NothingParked();

        return (requestContext, parked);
    }

    /// <summary>
    /// Takes the parked principal, which may have been re-parked since it was read. Taken by another
    /// post in the meantime refuses this one; the completion claim decides between two that both took it.
    /// </summary>
    private async Task<PendingTicket> TakeParkedAsync(HttpContext context, AuthorizationRequestContext requestContext) =>
        await _services.Flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false)
        ?? throw NothingParked();

    private static ZeeKayDaInteractionException UpstreamSubjectRefused() => new(
        "The replacement account's subject is the upstream subject the provider returned. The " +
        "session subject of an external sign-in is never the upstream one verbatim: pass a local " +
        "account's own subject, or let SignInAsync derive the subject.");

    private static NothingToContinueException NothingParked() => new(
        NothingToContinueReason.NothingParked,
        "No external sign-in is parked for this interaction: it expired, was already used, or the " +
        "user did not arrive here through RedirectToAsync. Send the user back to the login page.");

    /// <summary>Refuses, without taking it, a parked principal that <see cref="Promote"/> would refuse.</summary>
    private void RequirePromotable(PendingTicket parked) => Promote(parked);

    /// <summary>The principal to promote for a parked ticket, from a provider still registered.</summary>
    private ClaimsPrincipal Promote(PendingTicket ticket)
    {
        RequireRegistered(ticket);
        return ExternalSubject.ForPromotion(ticket.Provider, ticket.Principal);
    }

    /// <summary>Refuses a parked principal whose provider the host no longer registers.</summary>
    private void RequireRegistered(PendingTicket ticket)
    {
        if (_providers.Find(ticket.Provider) is null)
        {
            throw new ZeeKayDaInteractionException(
                "The provider that authenticated the parked principal is no longer registered, so the " +
                "sign-in cannot be finished. Send the user back to the login page.");
        }
    }

    private void RequireReplaceable(PendingTicket ticket, ClaimsPrincipal replacement)
    {
        RequireRegistered(ticket);
        if (CarriesUpstreamSubject(replacement, ticket.Principal))
            throw UpstreamSubjectRefused();
    }

    /// <summary>Whether the replacement's subject is, by value, a subject the provider returned.</summary>
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

    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "A sign-in or cancellation must come from a POST — the page's form submission — not " +
                "from the request that renders the page. Wire SignInAsync, SignInWithReplacedAccountAsync " +
                "and DenyAsync to the form's post handlers.");
        }

        return context;
    }
}
