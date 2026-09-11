using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="IProviderSignInInteraction"/> implementation: verifies the handoff, finds
/// the principal parked for the interaction, then promotes it with the framework's own subject,
/// promotes the host's replacement instead, or refuses the sign-in.
/// </summary>
internal sealed class ProviderSignInInteraction : IProviderSignInInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ProviderRegistry _providers;
    private readonly AuthorizationFlow _flow;
    private readonly InteractionOutcomes _outcomes;

    public ProviderSignInInteraction(
        IHttpContextAccessor httpContextAccessor,
        ProviderRegistry providers,
        AuthorizationFlow flow,
        InteractionOutcomes outcomes)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(providers);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(outcomes);

        _httpContextAccessor = httpContextAccessor;
        _providers = providers;
        _flow = flow;
        _outcomes = outcomes;
    }

    /// <inheritdoc/>
    public async Task<PendingPrincipal?> GetPendingPrincipalAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();
        var interactionId = await AuthorizationFlow.RequireInteractionIdAsync(context).ConfigureAwait(false);

        var pending = await _flow.ReadPendingAsync(context, interactionId, cancellationToken).ConfigureAwait(false);
        if (pending is null || _providers.Find(pending.Provider) is not { } registration)
            return null;

        return new PendingPrincipal(pending.Principal, registration.Descriptor);
    }

    /// <inheritdoc/>
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
        var (requestContext, parked) = await ResolveParkedAsync(context).ConfigureAwait(false);

        // Validated on the parked principal before it is taken, so a principal that cannot be
        // promoted stays where it is; built again from what was taken, so nothing stale is promoted.
        Promote(parked);
        var taken = await TakeParkedAsync(context, requestContext).ConfigureAwait(false);
        var promoted = Promote(taken);
        ((ClaimsIdentity)promoted.Identity!).AddClaims(collected.Where(claim => !ReservedClaims.IsReserved(claim)));

        // Nothing is stated about how the user proved who they are at the provider, as for an
        // external sign-in that involved no page.
        await _outcomes.CompleteSignInAsync(context, requestContext, new SignIn(promoted, AuthenticationMethods: [], taken.Provider))
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
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

        // A snapshot, of the identities since Clone shares them: what is validated is what is
        // promoted. Checked before the parked principal is taken: a principal the session would
        // refuse must not cost the page the one thing it needs to try again.
        var replacement = new ClaimsPrincipal(principal.Identities.Select(identity => identity.Clone()));
        if (!HasSubject(replacement))
        {
            throw new ZeeKayDaInteractionException(
                "The principal passed to SignInWithReplacedPrincipalAsync carries no subject. Add a 'sub' or " +
                $"'{ClaimTypes.NameIdentifier}' claim identifying the user.");
        }

        var context = RequireStateChangingRequest();
        var (requestContext, parked) = await ResolveParkedAsync(context).ConfigureAwait(false);

        RequireRegistered(parked);
        if (CarriesUpstreamSubject(replacement, parked.Principal))
        {
            throw new ZeeKayDaInteractionException(
                "The replacement principal's subject is the upstream subject the provider returned. The " +
                "session subject of an external sign-in is never the upstream one verbatim: pass a local " +
                "account's own principal, or let SignInAsync derive the subject.");
        }

        var taken = await TakeParkedAsync(context, requestContext).ConfigureAwait(false);

        await _outcomes.CompleteSignInAsync(context, requestContext, new SignIn(replacement, methods, taken.Provider))
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task DenyAsync()
    {
        var context = RequireStateChangingRequest();
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        await _outcomes.DenyAsync(context, requestContext, InteractionOutcomes.DeniedAfterProvider).ConfigureAwait(false);
    }

    /// <summary>
    /// The interaction the request is addressed to and the principal parked for it, read but not
    /// taken. A sign-in from this page finishes an external sign-in, so an interaction with
    /// nothing parked is refused before anything is promoted — the login page is where a sign-in
    /// from nothing belongs.
    /// </summary>
    private async Task<(AuthorizationRequestContext RequestContext, PendingTicket Parked)> ResolveParkedAsync(HttpContext context)
    {
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        var parked = await _flow.ReadPendingAsync(context, requestContext.Id, context.RequestAborted).ConfigureAwait(false)
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
        await _flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false)
        ?? throw NothingParked();

    private static ZeeKayDaInteractionException NothingParked() => new(
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

    private static bool HasSubject(ClaimsPrincipal principal) =>
        SubjectValues(principal).Any();

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
            "IProviderSignInInteraction requires an active HTTP request. Resolve it from request " +
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
