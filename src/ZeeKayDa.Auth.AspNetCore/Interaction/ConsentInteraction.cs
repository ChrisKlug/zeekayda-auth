using System.Collections.Immutable;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="IConsentInteraction"/> implementation: verifies the handoff and the session
/// behind it, then records the decision or ends the request.
/// </summary>
internal sealed class ConsentInteraction : IConsentInteraction
{
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

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthorizationFlow _flow;
    private readonly InteractionOutcomes _outcomes;

    public ConsentInteraction(
        IHttpContextAccessor httpContextAccessor,
        AuthorizationFlow flow,
        InteractionOutcomes outcomes)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(outcomes);

        _httpContextAccessor = httpContextAccessor;
        _flow = flow;
        _outcomes = outcomes;
    }

    /// <inheritdoc/>
    public async Task<ConsentRequest> GetRequestAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();
        var requestContext = await ResolveAsync(context).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        var client = await _flow.DescribeClientAsync(context, requestContext, cancellationToken).ConfigureAwait(false);

        // The subject was written by the same promotion that wrote the session identifier
        // ResolveAsync just matched, so it is present whenever that check passed.
        return new ConsentRequest(client, requestContext.Scopes.ToImmutableArray(), requestContext.Subject!);
    }

    /// <inheritdoc/>
    public async Task GrantAsync(IEnumerable<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        // Materialised and checked before anything is resolved, so a bad argument is blamed on
        // the caller's argument rather than surfacing as a mangled grant.
        var answered = scopes.ToArray();
        if (answered.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("An entry in scopes is null or blank.", nameof(scopes));

        var context = RequireHttpContext();
        var requestContext = await ResolveAsync(context).ConfigureAwait(false);

        // The page's answer can only narrow what was asked: intersected in request order, over
        // ordinal comparison, so a page cannot grant a scope the request never carried.
        var granted = requestContext.Scopes
            .Where(scope => answered.Contains(scope, StringComparer.Ordinal))
            .ToImmutableArray();

        if (!granted.Contains(StandardScopes.OpenId.Name, StringComparer.Ordinal))
        {
            await _outcomes.DenyAsync(context, requestContext, IdentityWithheld).ConfigureAwait(false);
            return;
        }

        await _outcomes.CompleteConsentAsync(context, requestContext, granted).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task DenyAsync()
    {
        var context = RequireHttpContext();
        var requestContext = await ResolveAsync(context).ConfigureAwait(false);

        await _outcomes.DenyAsync(context, requestContext, DeclinedAtConsent).ConfigureAwait(false);
    }

    /// <summary>
    /// The interaction this request may decide consent for: addressed by <c>zkd_i</c> on the
    /// login service's exact terms, and authenticated by the session this browser still holds.
    /// </summary>
    private async ValueTask<AuthorizationRequestContext> ResolveAsync(HttpContext context)
    {
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        if (!await _flow.IsAuthenticatedByCurrentSessionAsync(context, requestContext).ConfigureAwait(false))
        {
            throw new ZeeKayDaInteractionException(
                "The session that authenticated this authorization request is not the one this browser " +
                "holds: the user signed out, or signed in again as someone else, before answering the " +
                "consent page. Start the authorization request again.");
        }

        return requestContext;
    }

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "IConsentInteraction requires an active HTTP request. Resolve it from request services " +
            "inside the consent page, not from a background service.");
}
