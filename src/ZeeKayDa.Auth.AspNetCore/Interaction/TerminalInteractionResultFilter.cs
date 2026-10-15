using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Skips MVC's result for a request a terminal interaction call already answered, so a handler
/// can end with a plain <c>await</c> instead of rendering into the committed response.
/// </summary>
/// <remarks>
/// Always-run and ordered first, so it sees substituted results and no other result filter, a
/// host's included, runs. Keyed on <see cref="TerminalResponse"/>, not
/// <see cref="HttpResponse.HasStarted"/>, so a response the host started keeps MVC's behaviour.
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
/// Adds <see cref="TerminalInteractionResultFilter"/> to every MVC action.
/// </summary>
internal sealed class TerminalInteractionMvcOptionsSetup : IConfigureOptions<MvcOptions>
{
    public void Configure(MvcOptions options) => options.Filters.Add(new TerminalInteractionResultFilter());
}
