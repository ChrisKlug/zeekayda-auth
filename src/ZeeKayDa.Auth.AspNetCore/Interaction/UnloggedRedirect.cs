using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A redirect written without going through <see cref="Results.Redirect(string, bool, bool)"/>,
/// whose executor logs the full <c>Location</c> at <c>Information</c>. A response to a client
/// carries values that may not reach a log sink — an authorization code, the client's
/// <c>state</c> — so the framework writes the two headers itself.
/// </summary>
internal sealed class UnloggedRedirect(string location) : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        httpContext.Response.StatusCode = StatusCodes.Status302Found;
        httpContext.Response.Headers.Location = location;

        return Task.CompletedTask;
    }
}
