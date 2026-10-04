using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host error page's view of the authorization error it was asked to render. One of the
/// per-page interaction services: the host builds the page, this service supplies the protocol
/// data, and no host code ever reads a cookie or query parameter to get it.
/// </summary>
/// <remarks>
/// Used by the page at <c>AuthorizationEndpoint.Interaction.ErrorPath</c>. The framework
/// redirects there carrying only an opaque identifier; the details travel in an encrypted,
/// short-lived transport cookie that this service reads and verifies server-side. Error
/// descriptions are deliberately generic — phase-1 failures never distinguish an unknown client
/// from an unregistered redirect URI.
/// </remarks>
public sealed class ErrorInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthorizeErrorTransport _transport;

    internal ErrorInteraction(
        IHttpContextAccessor httpContextAccessor,
        AuthorizeErrorTransport transport)
    {
        _httpContextAccessor = httpContextAccessor;
        _transport = transport;
    }

    /// <summary>
    /// Returns the error details for the current request, or <see langword="null"/> when there
    /// are none — the transport cookie is absent, expired, or does not match the request's
    /// error identifier. A page receiving <see langword="null"/> should render a generic
    /// error message.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    public Task<AuthorizationErrorDetails?> GetErrorAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var context = _httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException(
                "ErrorInteraction requires an active HTTP request. Resolve it from request services " +
                "inside the error page, not from a background service.");

        return Task.FromResult(_transport.TryRead(context));
    }
}
