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
/// page left open past its lifetime, a bookmarked page — instead of letting the host page fail.
/// </summary>
/// <remarks>
/// <para>
/// A sign-in or consent step sends the user back to the client to start again, at the client's
/// registered <see cref="IClientMetadata.InitiateLoginUri"/> with <c>iss</c>, when the browser's
/// retired binding still names the client and the client registered one. Otherwise the user sees
/// the host's error page, or the framework's, with <see cref="AuthorizationErrorKind.NothingToContinue"/>.
/// </para>
/// <para>
/// A sign-out step shows the signed-out page when the browser holds no session, which is what
/// the user asked for. A browser that is still signed in is not told otherwise: it gets the error
/// page, and signing out is left to a fresh request, since the one it answered no longer exists
/// to say which session it was about.
/// </para>
/// </remarks>
internal sealed class NothingToContinue
{
    /// <summary>The error code a host's error page receives for an interaction there is nothing left of.</summary>
    internal const string ErrorCode = "interaction_not_found";

    private const string NoSignInToContinue =
        "There is no sign-in to continue. It expired, was already completed, or was started somewhere else.";

    private const string NoSignOutToContinue =
        "There is no sign-out to continue. It expired, or was started somewhere else. You are still signed in.";

    private readonly InteractionBindingCookie _binding;
    private readonly AuthorizationResponses _responses;
    private readonly EndSessionResponses _endSession;
    private readonly SsoSession _session;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ISanitizingLogger<NothingToContinue> _logger;

    public NothingToContinue(
        InteractionBindingCookie binding,
        AuthorizationResponses responses,
        EndSessionResponses endSession,
        SsoSession session,
        IOptions<AuthorizationServerOptions> options,
        ISanitizingLogger<NothingToContinue> logger)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(responses);
        ArgumentNullException.ThrowIfNull(endSession);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _binding = binding;
        _responses = responses;
        _endSession = endSession;
        _session = session;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Runs a sign-in or consent step, and answers the request itself when the step finds nothing
    /// to continue. Terminal either way.
    /// </summary>
    /// <param name="context">The request the host page is handling.</param>
    /// <param name="page">The page, as the log names it.</param>
    /// <param name="step">The step, which writes its own response when it completes.</param>
    public async Task SignInStepAsync(HttpContext context, string page, Func<Task> step)
    {
        try
        {
            await step().ConfigureAwait(false);
        }
        catch (NothingToContinueException missing) when (!context.Response.HasStarted)
        {
            Log(page, missing);

            var result = await RestartAtClientAsync(context).ConfigureAwait(false)
                ?? _responses.Local(context, AuthorizationErrorKind.NothingToContinue, ErrorCode, NoSignInToContinue);

            await WriteAsync(context, result).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs a sign-out step, and answers the request itself when the step finds nothing to
    /// continue. Terminal either way.
    /// </summary>
    public async Task SignOutStepAsync(HttpContext context, Func<Task> step)
    {
        try
        {
            await step().ConfigureAwait(false);
        }
        catch (NothingToContinueException missing) when (!context.Response.HasStarted)
        {
            Log("logout", missing);

            var result = await _session.ReadAsync(context).ConfigureAwait(false) is null
                ? _endSession.SignedOut()
                : _responses.Local(context, AuthorizationErrorKind.NothingToContinue, ErrorCode, NoSignOutToContinue);

            await WriteAsync(context, result).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Records that <paramref name="page"/> had nothing to continue. A missing <c>zkd_i</c> is the
    /// one case that may be the host's bug — a form that regenerates its action drops it — so it
    /// is a warning; everything else is a user doing something ordinary.
    /// </summary>
    public void Log(string page, NothingToContinueException missing)
    {
        if (missing.Reason == NothingToContinueReason.NoInteractionId)
        {
            _logger.LogWarning(
                "The {Page} page was reached without the '{Parameter}' parameter, so there was no interaction to " +
                "continue. A bookmarked page does this; so does a form whose action drops the parameter — pass it " +
                "back explicitly as a route value.",
                page,
                InteractionHandoff.InteractionIdParameter);
            return;
        }

        _logger.LogInformation(
            "The {Page} page was reached for an interaction there is nothing left of ({Reason}).",
            page,
            missing.Reason);
    }

    /// <summary>
    /// The client's login restart, when the browser's binding names a client that is still
    /// registered and registered an <see cref="IClientMetadata.InitiateLoginUri"/>. The destination
    /// comes from the registration, never from the request.
    /// </summary>
    private async ValueTask<IResult?> RestartAtClientAsync(HttpContext context)
    {
        var interactionId = await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false);
        if (interactionId is null || _binding.ReadClientId(context, interactionId) is not { } clientId)
            return null;

        var clients = context.RequestServices.GetRequiredService<ValidatedClientResolver>();
        var client = await clients.FindByClientIdAsync(clientId, context.RequestAborted).ConfigureAwait(false);
        if (client?.InitiateLoginUri is not { } initiateLoginUri)
            return null;

        return Results.Redirect(QueryHelpers.AddQueryString(initiateLoginUri, "iss", _options.Value.Issuer!));
    }

    private static async Task WriteAsync(HttpContext context, IResult result)
    {
        context.Response.Headers.CacheControl = "no-store";
        await result.ExecuteAsync(context).ConfigureAwait(false);
        await context.Response.StartAsync().ConfigureAwait(false);
        TerminalResponse.MarkCommitted(context);
    }
}
