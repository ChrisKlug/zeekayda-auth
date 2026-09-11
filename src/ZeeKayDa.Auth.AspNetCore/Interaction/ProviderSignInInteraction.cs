using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="IProviderSignInInteraction"/> implementation: verifies the handoff, finds
/// the principal parked for the interaction, then promotes it with the framework's own subject,
/// promotes the host's linked account instead, or refuses the sign-in.
/// </summary>
internal sealed class ProviderSignInInteraction : IProviderSignInInteraction
{
    /// <summary>
    /// The claim types that name the subject: refused among collected claims, since the
    /// framework derives the subject itself, and required on a linked principal. Compared
    /// ignoring case, as <see cref="ClaimsPrincipal"/> reads them back.
    /// </summary>
    private static readonly string[] SubjectClaimTypes = ["sub", ClaimTypes.NameIdentifier];

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
    public async Task<PendingPrincipal?> GetAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();
        var interactionId = await AuthorizationFlow.RequireInteractionIdAsync(context).ConfigureAwait(false);

        var pending = await _flow.ReadPendingAsync(context, interactionId, cancellationToken).ConfigureAwait(false);
        if (pending is null || _providers.Find(pending.Provider) is not { } registration)
            return null;

        return new PendingPrincipal(pending.Principal, registration.Descriptor);
    }

    /// <inheritdoc/>
    public async Task SignInAsync(params Claim[] claims)
    {
        ArgumentNullException.ThrowIfNull(claims);

        // A snapshot of the caller's array: what is validated is what is promoted, however the
        // caller's copy changes while the store is awaited. The subject is refused rather than
        // dropped: a page passing one expects it to be used, and silently replacing it would
        // hide the mistake this service exists to prevent.
        var collected = claims.ToArray();
        if (collected.Any(claim => claim is null))
            throw new ArgumentException("An entry in the collected claims is null.", nameof(claims));

        if (collected.Any(claim => IsSubject(claim.Type)))
        {
            throw new ArgumentException(
                "A collected claim names the subject. The session subject of an external sign-in is " +
                "derived by the framework from the provider, the issuer and the upstream subject; a " +
                "page that links the external identity to a local account passes that account's " +
                "principal to the other SignInAsync overload instead.",
                nameof(claims));
        }

        var context = RequireStateChangingRequest();
        var (requestContext, pending) = await TakeParkedAsync(context).ConfigureAwait(false);

        var promoted = ExternalSubject.ForPromotion(pending.Provider, pending.Principal);
        ((ClaimsIdentity)promoted.Identity!).AddClaims(collected.Where(claim => !ReservedClaims.IsReserved(claim)));

        // Nothing is stated about how the user proved who they are at the provider, as for an
        // external sign-in that involved no page.
        await _outcomes.CompleteSignInAsync(context, requestContext, promoted, authenticationMethods: [], pending.Provider)
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task SignInAsync(ClaimsPrincipal principal, params string[] authenticationMethods)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        var methods = authenticationMethods.ToArray();
        if (methods.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "An authentication method reference is null or blank. Pass a value such as "
                + "AuthenticationMethods.Password, or pass none to omit the amr claim.",
                nameof(authenticationMethods));

        // Checked before the parked principal is taken: a principal the session would refuse
        // must not cost the page the one thing it needs to try again.
        if (!HasSubject(principal))
        {
            throw new ZeeKayDaInteractionException(
                "The principal passed to SignInAsync carries no subject. Add a 'sub' or " +
                $"'{ClaimTypes.NameIdentifier}' claim identifying the user.");
        }

        var context = RequireStateChangingRequest();
        var (requestContext, pending) = await TakeParkedAsync(context).ConfigureAwait(false);

        await _outcomes.CompleteSignInAsync(context, requestContext, principal, methods, pending.Provider)
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
    /// The interaction the request is addressed to and the principal parked for it, taken out of
    /// the store: what is promoted is what was consumed, so a principal parked between a read and
    /// the completion cannot be discarded in favour of a stale one. A sign-in from this page
    /// finishes an external sign-in, so an interaction with nothing parked is refused before
    /// anything is promoted — the login page is where a sign-in from nothing belongs. Two posts
    /// that both take the principal both promote the same person; the completion claim decides
    /// which one issues.
    /// </summary>
    private async Task<(AuthorizationRequestContext RequestContext, PendingTicket Pending)> TakeParkedAsync(HttpContext context)
    {
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        var pending = await _flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                "No external sign-in is parked for this interaction: it expired, was already used, or the " +
                "user did not arrive here through RedirectToAsync. Send the user back to the login page.");

        return (requestContext, pending);
    }

    private static bool IsSubject(string claimType) => SubjectClaimTypes.Contains(claimType, StringComparer.OrdinalIgnoreCase);

    private static bool HasSubject(ClaimsPrincipal principal) =>
        SubjectClaimTypes.Any(type => !string.IsNullOrEmpty(principal.FindFirstValue(type)));

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
                "from the request that renders the page. Wire SignInAsync and DenyAsync to the form's " +
                "post handlers.");
        }

        return context;
    }
}
