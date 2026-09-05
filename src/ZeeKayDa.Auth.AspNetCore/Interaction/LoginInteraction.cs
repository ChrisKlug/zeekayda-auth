using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Default <see cref="ILoginInteraction"/> implementation: verifies the handoff, then signs the
/// user in, cancels the request, or sends the user out to an external provider.
/// </summary>
internal sealed class LoginInteraction : ILoginInteraction
{
    /// <summary>
    /// What a cancelled request tells the client. Names the stage as well as the outcome, so this
    /// reads differently from a consent denial or a policy refusal — all three are
    /// <c>access_denied</c> on the wire. Generic by construction: it echoes no value, and a client
    /// needing a stable discriminator gets the opt-in <c>zkd_error</c> sub-code, not this prose.
    /// </summary>
    private const string CancelledAtSignIn = "The user cancelled the request at the sign-in page.";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ProviderRegistry _providers;
    private readonly AuthorizationFlow _flow;
    private readonly InteractionOutcomes _outcomes;

    public LoginInteraction(
        IHttpContextAccessor httpContextAccessor,
        IOptions<AuthorizationServerOptions> options,
        ProviderRegistry providers,
        AuthorizationFlow flow,
        InteractionOutcomes outcomes)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(providers);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(outcomes);

        _httpContextAccessor = httpContextAccessor;
        _options = options;
        _providers = providers;
        _flow = flow;
        _outcomes = outcomes;
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

        var context = RequireStateChangingRequest();
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        // The host's principal is what the session holds; a provider that parked one for this
        // interaction is recorded on the request by the completion.
        await _outcomes.CompleteSignInAsync(context, requestContext, principal, authenticationMethods, providerScheme: null)
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
        var context = RequireStateChangingRequest();
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        await _outcomes.DenyAsync(context, requestContext, CancelledAtSignIn).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task ChallengeAsync(string provider)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);

        var context = RequireStateChangingRequest();
        var requestContext = await _flow.ResolveAddressedAsync(context).ConfigureAwait(false);

        // The identifier selects from the configured set; it never names a target. The value is
        // request input, so the message does not echo it.
        var registration = _providers.Find(provider)
            ?? throw new ZeeKayDaInteractionException(
                "The provider identifier is not one of the registered providers. Pass the Id of an " +
                "entry in ILoginInteraction.Providers, as the login page received it.");

        await _outcomes.ChallengeAsync(context, requestContext, registration).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<PendingPrincipal?> GetPendingPrincipalAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();
        var interactionId = await AuthorizationFlow.RequireInteractionIdAsync(context).ConfigureAwait(false);

        // The cookie read itself takes no token, so cancellation is honoured around it: nothing
        // is returned once the caller has stopped waiting.
        cancellationToken.ThrowIfCancellationRequested();
        var pending = await _flow.ReadPendingAsync(context, interactionId).WaitAsync(cancellationToken).ConfigureAwait(false);
        if (pending is null || _providers.Find(pending.Provider) is not { } registration)
            return null;

        return new PendingPrincipal(pending.Principal, registration.Descriptor);
    }

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "ILoginInteraction requires an active HTTP request. Resolve it from request services " +
            "inside the login page, not from a background service.");

    /// <summary>
    /// A terminal step is taken only from a form post. The framework arrives at the login page
    /// with a GET, and the framework's cookies accompany a top-level GET from anywhere, so a
    /// cancel or a sign-in wired to a link would be triggerable by a page that never showed the
    /// user anything. Checked before any state is read, so a wrongly wired page changes nothing.
    /// </summary>
    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "A sign-in, cancellation or provider choice must come from a POST — the login form's " +
                "submission — not from the request that renders the page. Wire SignInAsync, DenyAsync " +
                "and ChallengeAsync to the form's post handlers.");
        }

        return context;
    }

    /// <inheritdoc/>
    public bool LocalLoginEnabled => _options.Value.AuthorizationEndpoint.Interaction.SupportsLocalSignIn;

    /// <inheritdoc/>
    public IReadOnlyList<ProviderDescriptor> Providers => _providers.Descriptors;
}
