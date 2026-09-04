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
/// interaction it was asked to resume and a registered provider, gives the host its say through
/// <c>OnProviderSignIn</c>, and promotes the principal when the host does not end the request
/// itself.
/// </summary>
/// <remarks>
/// The ticket is signed out before anything is checked, so a refused one cannot be presented
/// again. A refusal renders the local error page and leaves the interaction untouched: a stray or
/// replayed request here can neither complete nor cancel a live authorization request.
/// </remarks>
internal sealed class ResumeEndpoint : IZeeKayDaEndpoint
{
    private const string NothingToResume =
        "There is no external sign-in to resume. Return to the application and try again.";

    private const string DidNotComplete =
        "Sign-in through the external identity provider did not complete. Return to the application and try again.";

    /// <summary>
    /// What a refusal after the provider tells the client. Names the stage, as the sign-in page's
    /// cancellation does, so a client can tell the two apart; framework-owned, so nothing a host
    /// or a provider said reaches the client, browser history or proxy logs.
    /// </summary>
    private const string DeniedAfterProvider =
        "The sign-in at the external identity provider was not accepted.";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly IOptions<ProviderOptions> _providerOptions;
    private readonly ProviderRegistry _providers;
    private readonly AuthorizationFlow _flow;
    private readonly LocalErrorResponse _localError;
    private readonly ClientErrorRedirect _clientError;
    private readonly SignInCompletion _completion;
    private readonly PendingPrincipalCookie _pending;
    private readonly ISanitizingLogger<ResumeEndpoint> _logger;

    public ResumeEndpoint(
        IOptions<AuthorizationServerOptions> options,
        IOptions<ProviderOptions> providerOptions,
        ProviderRegistry providers,
        AuthorizationFlow flow,
        LocalErrorResponse localError,
        ClientErrorRedirect clientError,
        SignInCompletion completion,
        PendingPrincipalCookie pending,
        ISanitizingLogger<ResumeEndpoint> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(providerOptions);
        ArgumentNullException.ThrowIfNull(providers);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(localError);
        ArgumentNullException.ThrowIfNull(clientError);
        ArgumentNullException.ThrowIfNull(completion);
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _providerOptions = providerOptions;
        _providers = providers;
        _flow = flow;
        _localError = localError;
        _clientError = clientError;
        _completion = completion;
        _pending = pending;
        _logger = logger;
    }

    /// <summary>The route under the issuer path, derived as every other endpoint's route is.</summary>
    public static string RouteFor(Uri issuerUri)
    {
        ArgumentNullException.ThrowIfNull(issuerUri);

        return EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, "/connect/resume");
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        // Nothing redirects here unless a provider was challenged, so a host without providers
        // serves no such route.
        if (_providers.Count == 0)
            return;

        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);

        // Typed as Delegate so the result-writing overload is chosen: a method taking only the
        // context also converts to RequestDelegate, whose overload discards the returned result.
        // AllowAnonymous so a host-wide authorization fallback policy cannot turn the return from
        // the provider into a challenge of the host's own scheme.
        Delegate handler = HandleAsync;
        endpoints.MapGet(RouteFor(issuerUri), handler)
            .RequireIssuerHost(issuerUri)
            .AllowAnonymous();
    }

    private async Task<IResult> HandleAsync(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";

        var interactionId = await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false);
        var result = await context.AuthenticateAsync(ZeeKayDaCookies.External).ConfigureAwait(false);

        // Single use, consumed whether or not it can be resumed.
        await context.SignOutAsync(ZeeKayDaCookies.External).ConfigureAwait(false);

        if (interactionId is null || !result.Succeeded || result.Ticket is null || result.Principal is null)
            return Refuse(context);

        var items = result.Ticket.Properties.Items;
        if (Item(items, ExternalTicket.InteractionIdItem) is not { } boundId
            || !InteractionHandoff.IdentifiersMatch(boundId, interactionId))
        {
            return Refuse(context);
        }

        var requestContext = _flow.Read(context);
        if (requestContext is null || !InteractionHandoff.IdentifiersMatch(requestContext.Id, interactionId))
            return Refuse(context);

        // The provider is what the callback endpoint recorded from its route. It must be the one
        // the challenge was issued to — a callback carried to another provider's route, with a
        // handler that accepts the state, cannot complete as that provider — and what the remote
        // handler stamped is a further cross-check.
        if (Item(items, ExternalTicket.ProviderItem) is not { } providerName
            || _providers.Find(providerName) is not { } registration
            || Item(items, ExternalTicket.ChallengedProviderItem) is not { } challenged
            || !string.Equals(challenged, providerName, StringComparison.Ordinal))
        {
            return Refuse(context);
        }

        if (Item(items, ExternalTicket.RemoteAuthenticationSchemeItem) is { } stamped
            && !string.Equals(stamped, providerName, StringComparison.Ordinal))
        {
            return Refuse(context);
        }

        // The host's callback gets a copy — of the identities, since ClaimsPrincipal.Clone shares
        // them. What is parked or promoted is the framework's own principal, so a reference the
        // host kept cannot change the session after the fact.
        var principal = ReservedClaims.Strip(result.Principal);
        var signIn = new ProviderSignInContext(
            new ClaimsPrincipal(principal.Identities.Select(identity => identity.Clone())),
            registration.Descriptor,
            new ClientInformation(requestContext.ClientId),
            requestContext.Scopes.ToImmutableArray(),
            context.RequestAborted,
            path => RedirectToAsync(context, requestContext, registration, principal, path),
            () => DenyAsync(context, requestContext));

        ClaimsPrincipal promoted;
        try
        {
            if (_providerOptions.Value.OnProviderSignIn is { } onProviderSignIn)
            {
                await onProviderSignIn(signIn).ConfigureAwait(false);
                if (signIn.Completed)
                    return Results.Empty;
            }

            promoted = ExternalSubject.ForPromotion(registration.Name, principal);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && !context.Response.HasStarted)
        {
            // The host's handler and the handler's principal are caller-supplied; a failure in
            // either renders locally like a callback failure does, and leaves the interaction
            // alive. A failure after a terminal call has committed the response cannot be
            // rendered over and propagates.
            return Fail(context, registration, ex);
        }

        // A parked principal bound to this interaction is consumed by whichever sign-in
        // completes it, the automatic one included.
        await _pending.ConsumeAsync(context, requestContext.Id).ConfigureAwait(false);

        // The framework states nothing about how the user proved who they are at the provider —
        // it was told nothing — so no amr is reported for an auto-promoted external sign-in.
        await _completion.CompleteAsync(
                context,
                requestContext,
                promoted,
                authenticationMethods: [],
                providerScheme: registration.Name)
            .ConfigureAwait(false);

        return Results.Empty;
    }

    private IResult Fail(HttpContext context, ProviderRegistration registration, Exception exception)
    {
        // The framework's own interaction exception carries framework text — which claim was
        // missing, and why — and goes through the sanitizing logger whole; anything else is
        // logged by type, since a host's or a provider's message may carry anything.
        if (exception is ZeeKayDaInteractionException interaction)
        {
            _logger.LogError(
                interaction,
                "Signing in through provider {Provider} was refused at promotion.",
                registration.Name);
        }
        else
        {
            _logger.LogError(
                "The sign-in handler for provider {Provider} failed with {ExceptionType}.",
                registration.Name,
                exception.GetType().FullName);
        }

        return _localError.Render(context, AuthorizeRequestErrors.ServerError, DidNotComplete);
    }

    private async Task RedirectToAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ProviderRegistration registration,
        ClaimsPrincipal principal,
        PathString path)
    {
        // The principal only: the ticket's properties and any tokens the provider saved into them
        // stay behind with the consumed external ticket.
        await _pending.WriteAsync(context, principal, requestContext.Id, registration.Name).ConfigureAwait(false);

        await TerminalResponse.WriteAsync(
                context,
                Results.Redirect(InteractionHandoff.BuildRedirectUrl(path.Value!, requestContext.Id)))
            .ConfigureAwait(false);
    }

    private async Task DenyAsync(HttpContext context, AuthorizationRequestContext requestContext)
    {
        // Discarded before the response is written, so a denied request cannot be resumed by a
        // later sign-in picking the context back up — nor by a parked principal bound to it. The
        // destination is the redirect URI read out of the encrypted context, never anything this
        // request supplied.
        _flow.Clear(context);
        await _pending.ConsumeAsync(context, requestContext.Id).ConfigureAwait(false);

        await TerminalResponse.WriteAsync(
                context,
                _clientError.To(
                    requestContext.RedirectUri,
                    AuthorizeRequestErrors.AccessDenied,
                    DeniedAfterProvider,
                    requestContext.State))
            .ConfigureAwait(false);
    }

    private IResult Refuse(HttpContext context) =>
        _localError.Render(context, AuthorizeRequestErrors.InvalidRequest, NothingToResume);

    private static string? Item(IDictionary<string, string?> items, string key) =>
        items.TryGetValue(key, out var value) && !string.IsNullOrEmpty(value) ? value : null;
}
