using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="IErrorInteraction"/> implementation reading the framework's encrypted
/// error-transport cookie for the current request.
/// </summary>
internal sealed class ErrorInteraction : IErrorInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthorizeErrorTransport _transport;

    public ErrorInteraction(IHttpContextAccessor httpContextAccessor, AuthorizeErrorTransport transport)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(transport);

        _httpContextAccessor = httpContextAccessor;
        _transport = transport;
    }

    /// <inheritdoc/>
    public ValueTask<AuthorizationErrorDetails?> GetErrorAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var context = _httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException(
                "IErrorInteraction requires an active HTTP request. Resolve it from request services " +
                "inside the error page, not from a background service.");

        return ValueTask.FromResult(_transport.TryRead(context));
    }
}
