using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A redirect that bypasses <see cref="Results.Redirect(string, bool, bool)"/>, whose executor
/// would log a <c>Location</c> carrying a code or <c>state</c>.
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
