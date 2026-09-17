using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="ILogoutInteraction"/> implementation: resolves the sign-out this browser was
/// sent to confirm, and ends the session when the user confirms it.
/// </summary>
internal sealed class LogoutInteraction : ILogoutInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly LogoutRequestStore _requests;
    private readonly EndSessionResponses _responses;
    private readonly SsoSession _session;
    private readonly NothingToContinue _nothingToContinue;

    public LogoutInteraction(
        IHttpContextAccessor httpContextAccessor,
        LogoutRequestStore requests,
        EndSessionResponses responses,
        SsoSession session,
        NothingToContinue nothingToContinue)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(requests);
        ArgumentNullException.ThrowIfNull(responses);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(nothingToContinue);

        _httpContextAccessor = httpContextAccessor;
        _requests = requests;
        _responses = responses;
        _session = session;
        _nothingToContinue = nothingToContinue;
    }

    /// <inheritdoc/>
    public async Task<LogoutRequest> GetRequestAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();

        cancellationToken.ThrowIfCancellationRequested();

        // The page takes a one-click decision, so it renders framed by nobody and cached by nothing
        // — stamped before the read, so a page rendering its own "nothing to confirm" is covered too.
        RenderedPage.Protect(context.Response);
        var request = await ResolveAddressedAsync(context, cancellationToken).ConfigureAwait(false);

        // Checked here and not only at SignOutAsync: the request names the user it was started for,
        // and a confirmation left open across a fresh sign-in would hand the new user the previous
        // one's subject. Refusing the render is also honest — the sign-out it asks about can no
        // longer complete.
        await RequireAskedSessionAsync(context, request, cancellationToken).ConfigureAwait(false);

        if (request.ClientId is null)
            return new LogoutRequest(client: null, request.Subject);

        var client = await FindClientAsync(context, request.ClientId, cancellationToken).ConfigureAwait(false);
        return new LogoutRequest(new ClientInformation(request.ClientId, client?.DisplayName), request.Subject);
    }

    /// <inheritdoc/>
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

    /// <inheritdoc/>
    public async Task SignOutAsync()
    {
        var context = RequireStateChangingRequest();
        await _nothingToContinue.SignOutStepAsync(context, () => ConfirmAsync(context)).ConfigureAwait(false);
    }

    private async Task ConfirmAsync(HttpContext context)
    {
        var request = await ResolveAddressedAsync(context, context.RequestAborted).ConfigureAwait(false);
        await RequireAskedSessionAsync(context, request, context.RequestAborted).ConfigureAwait(false);

        // Checked against the registration as it stands now rather than remembered from when the
        // sign-out arrived: an operator who removes a redirect URI means nobody to be sent there.
        var client = request.ClientId is null
            ? null
            : await FindClientAsync(context, request.ClientId, context.RequestAborted).ConfigureAwait(false);
        var redirect = PostLogoutRedirect.For(client, request.PostLogoutRedirectUri, request.State);

        await _requests.DeleteAsync(context, request.Id, context.RequestAborted).ConfigureAwait(false);
        var result = await _responses.SignOutAsync(context, redirect).ConfigureAwait(false);

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

        return await _requests.ReadAsync(context, interactionId, cancellationToken).ConfigureAwait(false)
            ?? throw new NothingToContinueException(
                NothingToContinueReason.NotFound,
                "There is no sign-out waiting to be confirmed with this identifier for this browser. It has " +
                "expired or already completed, the page was reached without going through the end-session " +
                "endpoint, or the sign-out was started in another browser.");
    }

    /// <summary>
    /// Refuses unless the browser still holds the session the sign-out was started for. A
    /// confirmation left open across a sign-out or a fresh sign-in would otherwise end a session
    /// nobody was asked about, and the answer to a question about a session that has since ended
    /// is not an instruction about its replacement. Reading the sign-out is gated on it too, so
    /// the subject it carries is only ever shown to the browser it was stored for.
    /// </summary>
    private async ValueTask RequireAskedSessionAsync(
        HttpContext context,
        LogoutRequestContext request,
        CancellationToken cancellationToken)
    {
        var session = await _session.ReadAsync(context).ConfigureAwait(false);
        if (session is not null && string.Equals(session.SessionId, request.SsoSessionId, StringComparison.Ordinal))
            return;

        // One answer either way: a sign-out that cannot be completed is not left for a later try.
        await _requests.DeleteAsync(context, request.Id, cancellationToken).ConfigureAwait(false);

        throw new NothingToContinueException(
            NothingToContinueReason.SessionChanged,
            "The session this sign-out was started for is not the one this browser holds now — it has " +
            "already ended, or the user signed in again since being asked. Start the sign-out again.");
    }

    /// <summary>
    /// The client's validated registration, resolved from the request's services for the reason
    /// <c>AuthorizationFlow.ResolveClientAsync</c> gives; <see langword="null"/> when it is no
    /// longer registered.
    /// </summary>
    private static ValueTask<IClientRegistration?> FindClientAsync(HttpContext context, string clientId, CancellationToken cancellationToken) =>
        context.RequestServices.GetRequiredService<ValidatedClientResolver>().FindByClientIdAsync(clientId, cancellationToken);

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "ILogoutInteraction requires an active HTTP request. Resolve it from request services inside " +
            "the logout page, not from a background service.");

    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "A sign-out must come from a POST — the logout form's submission — not from the request " +
                "that renders the page. Wire SignOutAsync to the form's post handler.");
        }

        return context;
    }
}
