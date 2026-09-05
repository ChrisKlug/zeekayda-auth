using System.Collections.Immutable;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="IConsentInteraction"/> implementation: verifies the handoff, the session
/// behind it and the client it is for, then records the decision or ends the request.
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

        cancellationToken.ThrowIfCancellationRequested();
        var (requestContext, client) = await ResolveAsync(context, cancellationToken).ConfigureAwait(false);

        ProtectRenderedPage(context.Response);

        // The subject was written by the same promotion that wrote the session identifier
        // ResolveAsync just matched, so it is present whenever that check passed.
        return new ConsentRequest(
            new ClientInformation(requestContext.ClientId, client.DisplayName),
            requestContext.Scopes.ToImmutableArray(),
            requestContext.Subject!);
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

        var context = RequireStateChangingRequest();
        var (requestContext, _) = await ResolveAsync(context, context.RequestAborted).ConfigureAwait(false);

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
        var context = RequireStateChangingRequest();
        var (requestContext, _) = await ResolveAsync(context, context.RequestAborted).ConfigureAwait(false);

        await _outcomes.DenyAsync(context, requestContext, DeclinedAtConsent).ConfigureAwait(false);
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
    private async ValueTask<(AuthorizationRequestContext RequestContext, IClientMetadata Client)> ResolveAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        if (!await _flow.IsAuthenticatedByCurrentSessionAsync(context, requestContext).ConfigureAwait(false))
        {
            throw new ZeeKayDaInteractionException(
                "The session that authenticated this authorization request is not the one this browser " +
                "holds: the user signed out, or signed in again as someone else, before answering the " +
                "consent page. Start the authorization request again.");
        }

        var client = await _flow.ResolveClientAsync(context, requestContext, cancellationToken).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                "The client that sent this authorization request is no longer registered, or no longer " +
                "lists its redirect URI, so there is nothing to consent to. Start the authorization " +
                "request again.");

        return (requestContext, client);
    }

    /// <summary>
    /// The consent page takes a one-click decision, so the response that renders it is framed by
    /// nobody and cached by nothing. No consent page can render without the call that stamps
    /// this, which is what makes it a guarantee rather than guidance. The frame-ancestors policy
    /// is appended, so a policy the host set of its own still applies alongside it.
    /// </summary>
    private static void ProtectRenderedPage(HttpResponse response)
    {
        var headers = response.Headers;
        headers.CacheControl = "no-store";
        headers.Append(HeaderNames.ContentSecurityPolicy, "frame-ancestors 'none'");
        headers.XFrameOptions = "DENY";
    }

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "IConsentInteraction requires an active HTTP request. Resolve it from request services " +
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
