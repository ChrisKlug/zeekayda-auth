using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="IErrorInteraction"/> implementation reading the framework's encrypted
/// error-transport cookie for the current request.
/// </summary>
internal sealed class ErrorInteraction(
    IHttpContextAccessor httpContextAccessor,
    AuthorizeErrorTransport transport) : IErrorInteraction
{
    /// <inheritdoc/>
    public ValueTask<AuthorizationErrorDetails?> GetErrorAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var context = httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException(
                "IErrorInteraction requires an active HTTP request. Resolve it from request services " +
                "inside the error page, not from a background service.");

        return ValueTask.FromResult(transport.TryRead(context));
    }
}
