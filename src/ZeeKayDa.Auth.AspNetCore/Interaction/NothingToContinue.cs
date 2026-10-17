using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Answers a page submitted for an interaction this browser no longer has — a double submit, a
/// page left open too long, a bookmark — instead of letting the host page fail.
/// </summary>
internal sealed class NothingToContinue(
    InteractionBindingCookie binding,
    InteractionAnswers answers,
    SsoSession session,
    IOptions<AuthorizationServerOptions> options,
    SanitizingLogger<NothingToContinue> logger)
{
    /// <summary>The error code a host's error page receives for an interaction there is nothing left of.</summary>
    internal const string ErrorCode = "interaction_not_found";

    private const string NoSignInToContinue =
        "There is no sign-in to continue. It expired, was already completed, or was started somewhere else.";

    private const string LogoutPage = "logout";

    private const string NoSignOutToContinue =
        "There is no sign-out to continue. It expired, or was started somewhere else. You are still signed in.";

    /// <summary>Runs a sign-in or consent step; with nothing to continue, restarts at the client or errors. Terminal.</summary>
    public Task SignInStepAsync(HttpContext context, string page, Func<Task> step) =>
        StepAsync(context, page, step, RestartOrErrorAsync);

    /// <summary>Runs a sign-out step; with nothing to continue, signed-out page or error. Terminal.</summary>
    public Task SignOutStepAsync(HttpContext context, Func<Task> step) =>
        StepAsync(context, LogoutPage, step, SignedOutOrErrorAsync);

    private async Task StepAsync(HttpContext context, string page, Func<Task> step, Func<HttpContext, ValueTask<IResult>> answer)
    {
        try
        {
            await step().ConfigureAwait(false);
        }
        catch (NothingToContinueException missing) when (!context.Response.HasStarted)
        {
            Log(page, missing);

            var result = await answer(context).ConfigureAwait(false);

            context.Response.Headers.CacheControl = "no-store";
            await result.ExecuteAsync(context).ConfigureAwait(false);
            await context.Response.StartAsync().ConfigureAwait(false);
            TerminalResponse.MarkCommitted(context);
        }
    }

    /// <summary>Back to the client to start again, or the error page.</summary>
    private async ValueTask<IResult> RestartOrErrorAsync(HttpContext context) =>
        await RestartAtClientAsync(context).ConfigureAwait(false)
        ?? answers.Authorization.Local(context, AuthorizationErrorKind.NothingToContinue, ErrorCode, NoSignInToContinue);

    /// <summary>The signed-out page for a browser that holds no session, and the error page for one that does.</summary>
    private async ValueTask<IResult> SignedOutOrErrorAsync(HttpContext context) =>
        (await session.ReadAsync(context).ConfigureAwait(false)).IsEmpty
            ? answers.EndSession.SignedOut()
            : answers.Authorization.Local(context, AuthorizationErrorKind.NothingToContinue, ErrorCode, NoSignOutToContinue);

    /// <summary>Logs a missing <c>zkd_i</c>, possibly the host's bug, as a warning; everything else is ordinary.</summary>
    public void Log(string page, NothingToContinueException missing) => Log(page, missing.Reason);

    /// <inheritdoc cref="Log(string, NothingToContinueException)"/>
    public void Log(string page, NothingToContinueReason reason)
    {
        if (reason == NothingToContinueReason.NoInteractionId)
        {
            logger.LogWarning(
                "The {Page} page was reached without the '{Parameter}' parameter, so there was no interaction to " +
                "continue. A bookmarked page does this; so does a form whose action drops the parameter — pass it " +
                "back explicitly as a route value.",
                page,
                InteractionHandoff.InteractionIdParameter);
            return;
        }

        logger.LogInformation(
            "The {Page} page was reached for an interaction there is nothing left of ({Reason}).",
            page,
            reason);
    }

    /// <summary>The registered <see cref="IClient.InitiateLoginUri"/> of the client the browser's binding names, if any.</summary>
    private async ValueTask<IResult?> RestartAtClientAsync(HttpContext context)
    {
        var interactionId = await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false);
        if (interactionId is null || binding.ReadClientId(context, interactionId) is not { } clientId)
            return null;

        var clients = context.RequestServices.GetRequiredService<ValidatedClientResolver>();
        var client = await clients.FindClientAsync(clientId, context.RequestAborted).ConfigureAwait(false);
        if (client?.InitiateLoginUri is not { } initiateLoginUri)
            return null;

        // Unlogged: a registered address may carry query values of its own.
        return new UnloggedRedirect(QueryHelpers.AddQueryString(initiateLoginUri, "iss", options.Value.Issuer!));
    }
}
