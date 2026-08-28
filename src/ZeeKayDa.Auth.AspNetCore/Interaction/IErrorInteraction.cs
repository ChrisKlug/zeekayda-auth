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
public interface IErrorInteraction
{
    /// <summary>
    /// Returns the error details for the current request, or <see langword="null"/> when there
    /// are none — the transport cookie is absent, expired, or does not match the request's
    /// error identifier. A page receiving <see langword="null"/> should render a generic
    /// error message.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask<AuthorizationErrorDetails?> GetErrorAsync(CancellationToken cancellationToken = default);
}
