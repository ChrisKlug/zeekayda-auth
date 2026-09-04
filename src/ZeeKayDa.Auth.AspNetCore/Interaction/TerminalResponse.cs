using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Writes a terminal response and commits it, so that it really is the last word on the request.
/// </summary>
/// <remarks>
/// Executing the result is not enough. A redirect sets the status and <c>Location</c> without
/// flushing, leaving <see cref="HttpResponse.HasStarted"/> false, so a host page that returns a
/// result of its own after calling a terminal method silently replaces both — which for a deny
/// is the open redirect the interaction identifier exists to prevent, written in host code where
/// nothing validates it. Starting the response commits the headers, turning that mistake into an
/// exception the first time the page is exercised.
/// </remarks>
internal static class TerminalResponse
{
    public static async Task WriteAsync(HttpContext context, IResult result)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(result);

        await result.ExecuteAsync(context).ConfigureAwait(false);
        await context.Response.StartAsync().ConfigureAwait(false);
    }
}
