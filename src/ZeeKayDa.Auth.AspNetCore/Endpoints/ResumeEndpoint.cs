using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The external-return landing pad, <c>/connect/resume</c>: routed, internal, never published in
/// discovery. A provider's handler ends its callback with a redirect here, carrying the ticket it
/// signed into <c>zkd.external</c>. This endpoint consumes that ticket, checks that it names the
/// interaction it was asked to resume and the registered provider it was issued to, gives the
/// host its say through <c>OnProviderSignIn</c>, and promotes the principal when the host does
/// not end the request itself.
/// </summary>
/// <remarks>
/// The ticket is signed out before anything is checked, so a refused one cannot be presented
/// again. A refusal renders the local error page and leaves the interaction untouched: a stray or
/// replayed request here can neither complete nor cancel a live authorization request.
/// </remarks>
internal sealed class ResumeEndpoint(
    IOptions<AuthorizationServerOptions> options,
    IOptions<ProviderOptions> providerOptions,
    ProviderRegistry providers,
    AuthorizationFlow flow,
    InteractionOutcomes outcomes,
    SanitizingLogger<ResumeEndpoint> logger) : IZeeKayDaEndpoint
{
    private const string NothingToResume =
        "There is no external sign-in to resume. Return to the application and try again.";

    private const string DidNotComplete =
        "Sign-in through the external identity provider did not complete. Return to the application and try again.";

    /// <summary>The route under the issuer path, derived as every other endpoint's route is.</summary>
    public static string RouteFor(Uri issuerUri)
    {
        ArgumentNullException.ThrowIfNull(issuerUri);

        return EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, "/connect/resume");
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        // Only a challenged provider redirects here.
        if (providers.Count == 0)
            return;

        var issuerUri = EndpointRouteHelper.GetIssuerUri(options);

        // As Delegate: a context-only method also converts to RequestDelegate, whose overload discards the result.
        Delegate handler = HandleAsync;
        endpoints.MapGet(RouteFor(issuerUri), handler)
            .RequireIssuerHost(issuerUri)
            .ExemptFromHostAuthorization();
    }

    internal async Task<IResult> HandleAsync(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";

        if (await ResolveTicketAsync(context).ConfigureAwait(false) is not { } resolved)
            return outcomes.LocalError(context, AuthorizeRequestErrors.InvalidRequest, NothingToResume);

        var (registration, requestContext, principal) = resolved;
        ProviderChallengeCookie.Clear(context, EndpointRouteHelper.GetIssuerUri(options), registration, requestContext.Id);

        string? claimsIssuer;
        ExternalIdentity identity;
        try
        {
            claimsIssuer = HandlerOptions.ClaimsIssuerOf(context.RequestServices, registration);
            identity = ExternalSubject.Identify(registration.Name, claimsIssuer, principal);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Fail(context, registration, ex);
        }

        // The host gets a snapshot, so a reference it keeps cannot change the session afterwards.
        var signIn = new ProviderSignInContext(
            identity,
            ReservedClaims.Snapshot(principal),
            registration.Descriptor,
            await flow.DescribeClientAsync(context, requestContext, context.RequestAborted).ConfigureAwait(false),
            requestContext.Scopes.ToImmutableArray(),
            context.RequestAborted,
            (path, placement) => outcomes.ParkAsync(context, requestContext, new PendingTicket(principal, registration.Name, placement), path),
            () => outcomes.DenyAsync(context, requestContext, Denial.RefusedAfterProvider));

        SessionSubject promoted;
        try
        {
            if (providerOptions.Value.OnProviderSignIn is { } onProviderSignIn)
            {
                await onProviderSignIn(signIn).ConfigureAwait(false);
                if (signIn.Completed)
                    return Results.Empty;
            }

            promoted = ExternalSubject.ForPromotion(registration.Name, claimsIssuer, principal);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && !context.Response.HasStarted)
        {
            // Renders locally and leaves the interaction alive; once a terminal call wrote the response, it propagates.
            return Fail(context, registration, ex);
        }

        // No amr: the provider told the framework nothing about how the user proved who they are.
        var promotion = new SignIn(promoted, new UserAuthentication(Methods: [], At: null), registration.Name, signIn.Placement);
        await SignInPromotedAsync(context, requestContext, promotion).ConfigureAwait(false);
        return Results.Empty;
    }

    /// <summary>Signs in the promoted subject, superseding a principal parked by an earlier return.</summary>
    private async Task SignInPromotedAsync(HttpContext context, AuthorizationRequestContext requestContext, SignIn promotion)
    {
        await flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false);
        await outcomes.CompleteSignInAsync(context, requestContext, promotion).ConfigureAwait(false);
    }

    /// <summary>
    /// Consumes the external ticket and checks what it names: the interaction this request was
    /// addressed with and the browser is carrying, and a registered provider that is both the one
    /// the challenge was issued to and the one whose callback route recorded it. Anything short of
    /// that is <see langword="null"/>, whatever else the ticket says.
    /// </summary>
    private async Task<ResolvedTicket?> ResolveTicketAsync(HttpContext context)
    {
        var (interactionId, ticket) = await ConsumeTicketAsync(context).ConfigureAwait(false);
        if (interactionId is null || ticket is null || !IsBoundTo(ticket, interactionId))
            return null;

        var requestContext = await flow.ReadAsync(context, interactionId).ConfigureAwait(false);
        if (requestContext is null)
            return null;

        if (ProviderOf(ticket.Properties.Items) is not { } registration)
            return null;

        return new ResolvedTicket(registration, requestContext, ReservedClaims.Strip(ticket.Principal));
    }

    /// <summary>
    /// The interaction this request is addressed with and the external ticket it carries. The
    /// ticket is single use, consumed whether or not it can be resumed.
    /// </summary>
    private static async Task<(string? InteractionId, AuthenticationTicket? Ticket)> ConsumeTicketAsync(HttpContext context)
    {
        var interactionId = await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false);
        var result = await context.AuthenticateAsync(ZeeKayDaCookies.External).ConfigureAwait(false);
        await context.SignOutAsync(ZeeKayDaCookies.External).ConfigureAwait(false);

        return (interactionId, result.Succeeded ? result.Ticket : null);
    }

    /// <summary>Whether the ticket names the interaction the request was addressed with.</summary>
    private static bool IsBoundTo(AuthenticationTicket ticket, string interactionId) =>
        Item(ticket.Properties.Items, ExternalTicket.InteractionIdItem) is { } bound
        && InteractionHandoff.IdentifiersMatch(bound, interactionId);

    /// <summary>
    /// The provider is what the callback endpoint recorded from its route. It must be the one the
    /// challenge was issued to — a callback carried to another provider's route, with a handler
    /// that accepts the state, cannot complete as that provider — and what a remote handler
    /// stamped for itself is a further cross-check.
    /// </summary>
    private ProviderRegistration? ProviderOf(IDictionary<string, string?> items)
    {
        if (Item(items, ExternalTicket.ProviderItem) is not { } providerName
            || Item(items, ExternalTicket.ChallengedProviderItem) is not { } challenged
            || !string.Equals(challenged, providerName, StringComparison.Ordinal))
        {
            return null;
        }

        if (Item(items, ExternalTicket.RemoteAuthenticationSchemeItem) is { } stamped
            && !string.Equals(stamped, providerName, StringComparison.Ordinal))
        {
            return null;
        }

        return providers.Find(providerName);
    }

    private IResult Fail(HttpContext context, ProviderRegistration registration, Exception exception)
    {
        // The framework's own exceptions carry its own text and are logged whole; anything else by type only.
        switch (exception)
        {
            case ZeeKayDaInteractionException interaction:
                logger.LogError(
                    interaction,
                    "Signing in through provider {Provider} was refused.",
                    registration.Name);
                break;

            case ZeeKayDaStoreException store:
                // The park write inside the host's RedirectToAsync: an outage, not a handler failure.
                logger.LogError(
                    store,
                    "Signing in through provider {Provider} failed because the interaction store could not be written.",
                    registration.Name);
                break;

            default:
                logger.LogError(
                    "The sign-in handler for provider {Provider} failed with {ExceptionType}.",
                    registration.Name,
                    exception.GetType().FullName);
                break;
        }

        return outcomes.LocalError(context, AuthorizeRequestErrors.ServerError, DidNotComplete);
    }

    private static string? Item(IDictionary<string, string?> items, string key) =>
        items.TryGetValue(key, out var value) && !string.IsNullOrEmpty(value) ? value : null;

    /// <summary>A ticket that passed every check: who it is for, who returned it, and what they returned.</summary>
    private sealed record ResolvedTicket(
        ProviderRegistration Registration,
        AuthorizationRequestContext RequestContext,
        ClaimsPrincipal Principal);
}
