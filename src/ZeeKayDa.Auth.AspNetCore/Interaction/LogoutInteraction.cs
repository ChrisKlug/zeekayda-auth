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

    public LogoutInteraction(
        IHttpContextAccessor httpContextAccessor,
        LogoutRequestStore requests,
        EndSessionResponses responses)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(requests);
        ArgumentNullException.ThrowIfNull(responses);

        _httpContextAccessor = httpContextAccessor;
        _requests = requests;
        _responses = responses;
    }

    /// <inheritdoc/>
    public async Task<LogoutRequest> GetRequestAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();

        cancellationToken.ThrowIfCancellationRequested();
        var request = await ResolveAddressedAsync(context, cancellationToken).ConfigureAwait(false);

        // The page takes a one-click decision, so it renders framed by nobody and cached by nothing.
        RenderedPage.Protect(context.Response);

        if (request.ClientId is null)
            return new LogoutRequest(client: null);

        var client = await FindClientAsync(context, request.ClientId, cancellationToken).ConfigureAwait(false);
        return new LogoutRequest(new ClientInformation(request.ClientId, client?.DisplayName));
    }

    /// <inheritdoc/>
    public async Task SignOutAsync()
    {
        var context = RequireStateChangingRequest();
        var request = await ResolveAddressedAsync(context, context.RequestAborted).ConfigureAwait(false);

        // Checked against the registration as it stands now rather than remembered from when the
        // sign-out arrived: an operator who removes a redirect URI means nobody to be sent there.
        var client = request.ClientId is null
            ? null
            : await FindClientAsync(context, request.ClientId, context.RequestAborted).ConfigureAwait(false);
        var redirectUri = client is not null
            && request.PostLogoutRedirectUri is { } uri
            && EndSessionResponses.IsRegistered(client, uri)
            ? uri
            : null;

        await _requests.DeleteAsync(context, request.Id, context.RequestAborted).ConfigureAwait(false);
        var result = await _responses.SignOutAsync(context, redirectUri, redirectUri is null ? null : request.State)
            .ConfigureAwait(false);

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
            ?? throw new ZeeKayDaInteractionException(
                $"This request carries no '{InteractionHandoff.InteractionIdParameter}' parameter, so there is " +
                "no sign-out to confirm. The framework adds it to the URL it redirects the logout page to; a " +
                "form that regenerates its action from routing drops it, and must pass it back explicitly " +
                $"(asp-route-{InteractionHandoff.InteractionIdParameter}).");

        return await _requests.ReadAsync(context, interactionId, cancellationToken).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                "There is no sign-out waiting to be confirmed with this identifier for this browser. It has " +
                "expired or already completed, the page was reached without going through the end-session " +
                "endpoint, or the sign-out was started in another browser.");
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
