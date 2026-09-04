using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="ILoginInteraction"/> implementation: verifies the handoff, then signs the
/// user in, cancels the request, or sends the user out to an external provider.
/// </summary>
/// <remarks>
/// Every read and write here is addressed by the interaction identifier the request carried —
/// never by "the current interaction". That is what keeps the backing swappable: a store-backed
/// context (#603) reads <em>an</em> interaction by id, and this code already asks for one.
/// </remarks>
internal sealed class LoginInteraction : ILoginInteraction
{
    /// <summary>
    /// What a cancelled request tells the client. Names the stage as well as the outcome, so this
    /// reads differently from a consent denial or a policy refusal — all three are
    /// <c>access_denied</c> on the wire. Generic by construction: it echoes no value, and a client
    /// needing a stable discriminator gets the opt-in <c>zkd_error</c> sub-code, not this prose.
    /// </summary>
    private const string CancelledAtSignIn = "The user cancelled the request at the sign-in page.";

    private const string NoHttpContext =
        "ILoginInteraction requires an active HTTP request. Resolve it from request services " +
        "inside the login page, not from a background service.";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuthorizationFlow _flow;
    private readonly ClientErrorRedirect _clientError;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ProviderRegistry _providers;
    private readonly SignInCompletion _completion;
    private readonly ProviderChallenge _challenge;
    private readonly PendingPrincipalCookie _pending;

    public LoginInteraction(
        IHttpContextAccessor httpContextAccessor,
        AuthorizationFlow flow,
        ClientErrorRedirect clientError,
        IOptions<AuthorizationServerOptions> options,
        ProviderRegistry providers,
        SignInCompletion completion,
        ProviderChallenge challenge,
        PendingPrincipalCookie pending)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(clientError);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(providers);
        ArgumentNullException.ThrowIfNull(completion);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(pending);

        _httpContextAccessor = httpContextAccessor;
        _flow = flow;
        _clientError = clientError;
        _options = options;
        _providers = providers;
        _completion = completion;
        _challenge = challenge;
        _pending = pending;
    }

    /// <inheritdoc/>
    public async Task SignInAsync(ClaimsPrincipal principal, params string[] authenticationMethods)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        // Caught here rather than at the claim write so the blame lands on the caller's
        // argument, not on a malformed session cookie several frames later.
        if (authenticationMethods.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "An authentication method reference is null or blank. Pass a value such as "
                + "AuthenticationMethods.Password, or pass none to omit the amr claim.",
                nameof(authenticationMethods));

        var context = RequireHttpContext();
        var requestContext = await ResolveInteractionAsync(context).ConfigureAwait(false);

        // A parked external principal is single-use and consumed by whichever sign-in completes
        // its interaction. The host's principal is what the session holds; the provider that
        // started the sign-in is still recorded on the request.
        var pending = await _pending.ConsumeAsync(context, requestContext.Id).ConfigureAwait(false);

        await _completion.CompleteAsync(context, requestContext, principal, authenticationMethods, pending?.Provider)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Ends the interaction the request is addressed to, telling the client the user did not
    /// authorize it. Resolution and the <c>zkd_i</c> binding are exactly as they are for a
    /// sign-in: a deny that could be aimed at another tab's request is a cross-tab denial of
    /// service.
    /// </summary>
    public async Task DenyAsync()
    {
        var context = RequireHttpContext();
        var requestContext = await ResolveInteractionAsync(context).ConfigureAwait(false);

        context.Response.Headers.CacheControl = "no-store";

        // Discarded before the response is written, so a cancelled request cannot be resumed by a
        // later sign-in picking the context back up — nor by a parked principal bound to it.
        _flow.Clear(context);
        await _pending.ConsumeAsync(context, requestContext.Id).ConfigureAwait(false);

        // The destination is the redirect URI phase 1 matched against the registration, read back
        // out of the encrypted context — never anything this request supplied. No session is
        // promoted and none is read: a user cancelling here is not signed in, and a user who was
        // already signed in elsewhere stays that way.
        await TerminalResponse.WriteAsync(
            context,
            _clientError.To(
                requestContext.RedirectUri,
                AuthorizeRequestErrors.AccessDenied,
                CancelledAtSignIn,
                requestContext.State))
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task ChallengeAsync(string provider)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);

        var context = RequireHttpContext();
        var requestContext = await ResolveInteractionAsync(context).ConfigureAwait(false);

        // The identifier selects from the configured set; it never names a target. The value is
        // request input, so the message does not echo it.
        var registration = _providers.Find(provider)
            ?? throw new ZeeKayDaInteractionException(
                "The provider identifier is not one of the registered providers. Pass the Id of an " +
                "entry in ILoginInteraction.Providers, as the login page received it.");

        context.Response.Headers.CacheControl = "no-store";

        await _challenge.ChallengeAsync(context, requestContext, registration).ConfigureAwait(false);
        await context.Response.StartAsync().ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<PendingPrincipal?> GetPendingPrincipalAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();
        var interactionId = await RequireInteractionIdAsync(context).ConfigureAwait(false);

        // The cookie read itself takes no token, so cancellation is honoured around it: nothing
        // is returned once the caller has stopped waiting.
        cancellationToken.ThrowIfCancellationRequested();
        var pending = await _pending.ReadAsync(context, interactionId).WaitAsync(cancellationToken).ConfigureAwait(false);
        if (pending is null || _providers.Find(pending.Provider) is not { } registration)
            return null;

        return new PendingPrincipal(pending.Principal, registration.Descriptor);
    }

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(NoHttpContext);

    /// <summary>
    /// Resolves the interaction this request is entitled to complete: the one the framework sent
    /// the user here for, named by <c>zkd_i</c> and confirmed against the identifier inside the
    /// encrypted context.
    /// </summary>
    private async ValueTask<AuthorizationRequestContext> ResolveInteractionAsync(HttpContext context)
    {
        var interactionId = await RequireInteractionIdAsync(context).ConfigureAwait(false);

        var requestContext = _flow.Read(context)
            ?? throw new ZeeKayDaInteractionException(
                "There is no active interaction to complete. The authorization request has expired, or " +
                "the login page was reached without going through /connect/authorize.");

        if (!InteractionHandoff.IdentifiersMatch(requestContext.Id, interactionId))
            throw new ZeeKayDaInteractionException(
                "The interaction this request names is not the one this browser is carrying. This is what " +
                "a second sign-in tab looks like: complete the authorization request that was started " +
                "most recently, or start a new one.");

        return requestContext;
    }

    private static async ValueTask<string> RequireInteractionIdAsync(HttpContext context) =>
        await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                $"This request carries no '{InteractionHandoff.InteractionIdParameter}' parameter, so there " +
                "is no interaction to complete. The framework adds it to the URL it redirects the login " +
                "page to; a form that regenerates its action from routing drops it, and must pass it back " +
                $"explicitly (asp-route-{InteractionHandoff.InteractionIdParameter}).");

    /// <inheritdoc/>
    public bool LocalLoginEnabled => _options.Value.AuthorizationEndpoint.Interaction.SupportsLocalSignIn;

    /// <inheritdoc/>
    public IReadOnlyList<ProviderDescriptor> Providers => _providers.Descriptors;
}
