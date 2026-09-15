using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Skips MVC's result for a request a terminal interaction call already answered, so a Razor
/// Pages handler or controller action can end with a plain <c>await</c> after one. Without it, a
/// page handler returning <see cref="Task"/> means "render this page", which throws against the
/// committed response.
/// </summary>
/// <remarks>
/// Always-run, so it also sees a result another filter substituted, and ordered first, so no other
/// result filter touches a response that is already complete. Keyed on
/// <see cref="TerminalResponse"/> rather than <see cref="HttpResponse.HasStarted"/>: an action
/// that started its own response for another reason keeps MVC's ordinary behaviour. Cancelling
/// from the front means no other result filter runs on such a request, a host's included — and a
/// result an exception filter substituted is skipped too, since it could not reach the browser.
/// </remarks>
internal sealed class TerminalInteractionResultFilter : IAlwaysRunResultFilter, IOrderedFilter
{
    public void OnResultExecuting(ResultExecutingContext context)
    {
        if (TerminalResponse.IsCommitted(context.HttpContext))
            context.Cancel = true;
    }

    public void OnResultExecuted(ResultExecutedContext context)
    {
    }

    public int Order => int.MinValue;
}

/// <summary>
/// Adds <see cref="TerminalInteractionResultFilter"/> to every MVC action. Only MVC reads
/// <see cref="MvcOptions"/>, so on a host without it this never runs.
/// </summary>
internal sealed class TerminalInteractionMvcOptionsSetup : IConfigureOptions<MvcOptions>
{
    public void Configure(MvcOptions options) => options.Filters.Add(new TerminalInteractionResultFilter());
}
