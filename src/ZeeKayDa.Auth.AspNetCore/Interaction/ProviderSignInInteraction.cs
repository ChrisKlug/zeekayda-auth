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
    /// The claim types that name the subject, which the framework derives itself for a parked
    /// principal. Compared ignoring case, as <see cref="ClaimsPrincipal"/> reads them back.
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

        // Caught here rather than at promotion so the blame lands on the caller's argument. The
        // subject is refused rather than dropped: a page passing one expects it to be used, and
        // silently replacing it would hide the mistake this service exists to prevent.
        if (claims.Any(claim => claim is null))
            throw new ArgumentException("An entry in the collected claims is null.", nameof(claims));

        if (claims.Any(claim => SubjectClaimTypes.Contains(claim.Type, StringComparer.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(
                "A collected claim names the subject. The session subject of an external sign-in is " +
                "derived by the framework from the provider, the issuer and the upstream subject; a " +
                "page that links the external identity to a local account passes that account's " +
                "principal to the other SignInAsync overload instead.",
                nameof(claims));
        }

        var context = RequireStateChangingRequest();
        var (requestContext, pending) = await ResolveParkedAsync(context).ConfigureAwait(false);

        var promoted = ExternalSubject.ForPromotion(pending.Provider, pending.Principal);
        ((ClaimsIdentity)promoted.Identity!).AddClaims(claims.Where(claim => !ReservedClaims.IsReserved(claim)));

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

        if (authenticationMethods.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "An authentication method reference is null or blank. Pass a value such as "
                + "AuthenticationMethods.Password, or pass none to omit the amr claim.",
                nameof(authenticationMethods));

        var context = RequireStateChangingRequest();
        var (requestContext, pending) = await ResolveParkedAsync(context).ConfigureAwait(false);

        await _outcomes.CompleteSignInAsync(context, requestContext, principal, authenticationMethods, pending.Provider)
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
    /// The interaction the request is addressed to and the principal parked for it. A sign-in
    /// from this page finishes an external sign-in, so an interaction with nothing parked is
    /// refused before anything is promoted: the login page is where a sign-in from nothing
    /// belongs. The principal is read here and consumed by the completion, so whichever of two
    /// posts loses the completion claim has promoted nothing.
    /// </summary>
    private async Task<(AuthorizationRequestContext RequestContext, PendingTicket Pending)> ResolveParkedAsync(HttpContext context)
    {
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        var pending = await _flow.ReadPendingAsync(context, requestContext.Id, context.RequestAborted).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                "No external sign-in is parked for this interaction: it expired, was already used, or the " +
                "user did not arrive here through RedirectToAsync. Send the user back to the login page.");

        return (requestContext, pending);
    }

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
