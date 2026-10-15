using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// One endpoint per registered provider at <c>/connect/callback/{provider}</c>, the route pinned
/// into the handler's <c>CallbackPath</c>; the handler completes the protocol and redirects to
/// <c>/connect/resume</c>.
/// </summary>
/// <remarks>
/// A failure returns to the login page when the browser carries its interaction, reaches the
/// client as <c>access_denied</c> for a refusal with no login page, and otherwise renders locally,
/// leaving the interaction untouched. Failures are logged by type: a message embeds what the
/// provider said.
/// </remarks>
internal sealed class ProviderCallbackEndpoint(
    IOptions<AuthorizationServerOptions> options,
    ProviderRegistry providers,
    ProviderHandlerActivator activator,
    AuthorizationFlow flow,
    InteractionOutcomes outcomes,
    SanitizingLogger<ProviderCallbackEndpoint> logger) : IZeeKayDaEndpoint
{
    private const string DidNotComplete =
        "Sign-in at the external identity provider did not complete. Return to the application and try again.";

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(options);

        foreach (var registration in providers.Registrations)
        {
            var route = ProviderCallbackRoute.For(issuerUri, registration.Name);

            // As Delegate: a context-only lambda also converts to RequestDelegate, whose overload discards the result.
            Delegate handler = (HttpContext context) => HandleAsync(context, registration);
            endpoints.MapMethods(route.Value!, [HttpMethods.Get, HttpMethods.Post], handler)
                .RequireIssuerHost(issuerUri)
                .ExemptFromHostAuthorization();
        }
    }

    private async Task<IResult> HandleAsync(HttpContext context, ProviderRegistration registration)
    {
        context.Response.Headers.CacheControl = "no-store";

        // The provider is what the route says, never what the request or the handler says.
        var feature = new ProviderCallbackFeature(registration, ProviderChallengeCookie.Single(context));
        context.Features.Set(feature);

        // Activation runs caller-supplied code too, so it is guarded with the rest.
        bool handled;
        try
        {
            var handler = await activator.ActivateAsync(context, registration).ConfigureAwait(false);
            if (handler is not IAuthenticationRequestHandler requestHandler)
            {
                logger.LogError(
                    "The handler for provider {Provider} does not handle requests, so its callback cannot be completed.",
                    registration.Name);
                return await DeclineAsync(context).ConfigureAwait(false);
            }

            handled = await requestHandler.HandleRequestAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return await FailAsync(context, feature, ex).ConfigureAwait(false);
        }

        ForgetChallengeIfFailed(context, feature);

        if (handled)
            return Results.Empty;

        logger.LogError("The handler for provider {Provider} declined its own callback.", registration.Name);
        return await DeclineAsync(context).ConfigureAwait(false);
    }

    /// <summary>Removes the challenge cookie of a failure a host's own event answered, bypassing <see cref="FailAsync"/>.</summary>
    private void ForgetChallengeIfFailed(HttpContext context, ProviderCallbackFeature feature)
    {
        if (context.Response.HasStarted)
            return;

        if (feature.FailedChallengeInteractionId is { } interactionId)
            ProviderChallengeCookie.Clear(context, EndpointRouteHelper.GetIssuerUri(options), feature.Provider, interactionId);
    }

    /// <summary>
    /// Discards the external ticket this request wrote, if any, so resume cannot promote an
    /// incomplete callback, but never one an earlier callback left the browser with.
    /// </summary>
    private static async Task DiscardTicketAsync(HttpContext context)
    {
        if (context.Response.HasStarted)
            return;

        var wroteTicket = context.Response.Headers.SetCookie
            .Any(cookie => cookie is not null && IsExternalTicketCookie(cookie));

        if (wroteTicket)
            await context.SignOutAsync(ZeeKayDaCookies.External).ConfigureAwait(false);
    }

    /// <summary>The external ticket cookie or one of its chunks (<c>zkd.externalC1</c>, …).</summary>
    private static bool IsExternalTicketCookie(string setCookie)
    {
        var name = setCookie.AsSpan()[..Math.Max(0, setCookie.IndexOf('='))];
        if (name.SequenceEqual(ZeeKayDaCookies.External))
            return true;

        var chunkPrefix = ZeeKayDaCookies.External + "C";
        return name.StartsWith(chunkPrefix, StringComparison.Ordinal)
            && name.Length > chunkPrefix.Length
            && name[chunkPrefix.Length..].ToString().All(char.IsAsciiDigit);
    }

    private static async Task<IResult> DeclineAsync(HttpContext context)
    {
        await DiscardTicketAsync(context).ConfigureAwait(false);
        return Results.NotFound();
    }

    private async Task<IResult> FailAsync(HttpContext context, ProviderCallbackFeature feature, Exception exception)
    {
        await DiscardTicketAsync(context).ConfigureAwait(false);
        LogFailure(feature, exception);

        if (await ReturnToLoginAsync(context, feature).ConfigureAwait(false) is { } returned)
            return returned;

        if (!feature.Refused)
            return outcomes.LocalError(context, AuthorizeRequestErrors.ServerError, DidNotComplete);

        // Decided on the refused challenge's own properties, never the challenge cookie.
        var refused = await ReadBoundAsync(context, feature.RefusedInteractionId).ConfigureAwait(false);
        if (refused is null)
            return outcomes.LocalError(context, AuthorizeRequestErrors.AccessDenied, Denial.DeclinedAtProvider.Description);

        return await outcomes.DeniedAtClientAfterClearingAsync(context, refused, Denial.DeclinedAtProvider).ConfigureAwait(false);
    }

    private void LogFailure(ProviderCallbackFeature feature, Exception exception)
    {
        if (feature.Refused)
        {
            logger.LogInformation("The user declined to sign in at provider {Provider}.", feature.Provider.Name);
            return;
        }

        logger.LogError(
            "The handler for provider {Provider} failed its callback with {ExceptionType}.",
            feature.Provider.Name,
            exception.GetType().FullName);
    }

    /// <summary>
    /// Back to the login page, or <see langword="null"/> without one or without the interaction's
    /// binding cookie, which a cross-site form_post callback does not carry.
    /// </summary>
    private async Task<IResult?> ReturnToLoginAsync(HttpContext context, ProviderCallbackFeature feature)
    {
        if (!outcomes.ReturnsToLoginPage)
            return null;

        var returning = await ReadBoundAsync(context, feature.ReturnInteractionId).ConfigureAwait(false);
        if (returning is null)
            return null;

        var outcome = feature.Refused ? ProviderReturnOutcome.Declined : ProviderReturnOutcome.Failed;
        return await outcomes.ReturnToLoginAsync(context, returning, feature.Provider, outcome).ConfigureAwait(false);
    }

    private async ValueTask<AuthorizationRequestContext?> ReadBoundAsync(HttpContext context, string? interactionId) =>
        interactionId is null ? null : await flow.ReadAsync(context, interactionId).ConfigureAwait(false);
}
