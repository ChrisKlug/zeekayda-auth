using System.Collections.Frozen;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Runs <see cref="ProviderOptions.OnProviderChallenge"/> and decides whether the challenge may be
/// sent; fail-closed, so a re-authentication demand nobody claimed to forward is never challenged.
/// </summary>
internal sealed class ProviderChallengeHook(
    IOptions<ProviderOptions> options,
    AuthorizationFlow flow,
    SanitizingLogger<ProviderChallengeHook> logger)
{
    private static readonly ChallengeRefusal NotReauthenticated = new(
        AuthorizeRequestErrors.LoginRequired,
        "The request requires the user to re-authenticate, and the external identity provider was not asked to.");

    private static readonly ChallengeRefusal Refused = new(
        AuthorizeRequestErrors.LoginRequired,
        "The authorization server did not send the user to the external identity provider.");

    private static readonly ChallengeRefusal HookFailed = new(
        AuthorizeRequestErrors.ServerError,
        "The authorization server could not prepare the external sign-in.");

    /// <summary>Why the challenge must not be sent, or <see langword="null"/> when it may.</summary>
    public async Task<ChallengeRefusal?> RefusalAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ProviderRegistration registration,
        AuthenticationProperties properties)
    {
        var session = await flow.ReadSessionAsync(context).ConfigureAwait(false);
        var reauthenticationRequired = flow.RequiresReauthentication(requestContext.Prompts, requestContext.MaxAge, session);

        var hook = options.Value.OnProviderChallenge;
        if (hook is null)
            return reauthenticationRequired ? NotReauthenticated : null;

        var challenge = new ProviderChallengeContext(
            registration.Descriptor,
            requestContext.Prompts.ToFrozenSet(),
            requestContext.MaxAge,
            requestContext.LoginHint,
            reauthenticationRequired,
            properties);

        if (Invoke(hook, challenge, registration) is not { } outcome)
            return HookFailed;

        if (outcome == ProviderChallengeOutcome.Refuse)
            return Refused;

        return reauthenticationRequired && outcome != ProviderChallengeOutcome.Reauthenticating ? NotReauthenticated : null;
    }

    /// <summary>The hook's outcome, or <see langword="null"/> when it threw or returned none.</summary>
    private ProviderChallengeOutcome? Invoke(
        Func<ProviderChallengeContext, ProviderChallengeOutcome> hook,
        ProviderChallengeContext challenge,
        ProviderRegistration registration)
    {
        ProviderChallengeOutcome? outcome;
        try
        {
            outcome = hook(challenge);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                "The challenge handler for provider {Provider} failed with {ExceptionType}.",
                registration.Name,
                ex.GetType().FullName);
            return null;
        }

        if (outcome is null)
            logger.LogError("The challenge handler for provider {Provider} returned no outcome.", registration.Name);

        return outcome;
    }
}

/// <summary>The error the client is answered with in place of a challenge.</summary>
internal sealed record ChallengeRefusal(string Error, string Description);
