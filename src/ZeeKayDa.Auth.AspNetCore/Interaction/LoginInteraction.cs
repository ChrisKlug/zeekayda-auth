using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host login page's completion of an authorization request. One of the per-page interaction
/// services: the host owns the page, the credential check and the user store; this service owns
/// the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page needs no <c>ReturnUrl</c>, no scheme name and no cookie name — the framework redirected
/// the user here and knows which authorization request is being resumed. The one thing the page
/// must preserve is the <c>zkd_i</c> query parameter it was reached with, which an ordinary
/// <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — the request carries no <c>zkd_i</c>; the interaction expired, was
/// already completed or was started in another browser; or another response completed it while
/// this one was being prepared — the framework answers the request itself. It sends the browser to
/// the client's registered <c>InitiateLoginUri</c>, with <c>iss</c>, to start again when the browser
/// can still say which client it came from, and to the error page with
/// <see cref="AuthorizationErrorKind.NothingToContinue"/> otherwise. The call is terminal either way.
/// A missing <c>zkd_i</c> is also logged as a warning, since a form that drops it causes the same
/// answer on every submission.
/// </para>
/// </remarks>
public sealed class LoginInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ProviderRegistry _providers;
    private readonly PageInteractionServices _services;

    internal LoginInteraction(
        IHttpContextAccessor httpContextAccessor,
        IOptions<AuthorizationServerOptions> options,
        ProviderRegistry providers,
        PageInteractionServices services)
    {
        _httpContextAccessor = httpContextAccessor;
        _options = options;
        _providers = providers;
        _services = services;
    }

    private const string Page = "login";

    /// <summary>
    /// What the page should render for: the client, the ways the user can sign in, and how their
    /// last trip to an external provider ended when it brought them back here.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// The page takes credentials, so the response this is called from is marked unframeable
    /// (<c>Content-Security-Policy: frame-ancestors 'none'</c>, appended alongside any policy of
    /// the host's, and <c>X-Frame-Options: DENY</c>) and uncacheable (<c>Cache-Control:
    /// no-store</c>).
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to sign in for: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, or was
    /// started in another browser. A page that wants to render its own message for these cases
    /// calls <see cref="TryGetRequestAsync"/> instead.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: nothing is reported as absent.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    public async Task<LoginRequest> GetRequestAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();

        cancellationToken.ThrowIfCancellationRequested();

        // Stamped before the read, so whatever the page renders — the form, or its own "nothing to
        // continue" after TryGetRequestAsync — is framed by nobody and cached by nothing.
        RenderedPage.Protect(context.Response);
        var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);
        var client = await _services.Flow.DescribeClientAsync(context, requestContext, cancellationToken).ConfigureAwait(false);

        return new LoginRequest(
            client,
            _providers.Descriptors,
            _options.Value.AuthorizationEndpoint.Interaction.SupportsLocalSignIn,
            ProviderReturnOf(requestContext.ProviderAttempt),
            requestContext.LoginHint);
    }

    /// <summary>
    /// What the page should render for, or <see langword="null"/> when there is no interaction to
    /// sign in for — for a page that renders its own "nothing to continue" message.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// Exactly <see cref="GetRequestAsync"/>, including the headers it stamps, except that each case
    /// <see cref="GetRequestAsync"/> reports with <see cref="ZeeKayDaInteractionException"/> returns
    /// <see langword="null"/> instead. A request with no <c>zkd_i</c> is logged as a warning, since
    /// a form that drops it looks like this on every submission.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: nothing is reported as absent.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    public async Task<LoginRequest?> TryGetRequestAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await GetRequestAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (NothingToContinueException missing)
        {
            _services.NothingToContinue.Log(Page, missing);
            return null;
        }
    }

    private ProviderReturn? ProviderReturnOf(ProviderAttempt? attempt) =>
        attempt is not null && _providers.Find(attempt.Provider) is { } registration
            ? new ProviderReturn(
                registration.Descriptor,
                attempt.Declined ? ProviderReturnOutcome.Declined : ProviderReturnOutcome.Failed)
            : null;

    /// <summary>
    /// Establishes the SSO session for <paramref name="subject"/>, authenticated by
    /// <paramref name="authenticationMethod"/>, and continues the authorization request that led
    /// here.
    /// </summary>
    /// <param name="subject">
    /// The user's identifier, which the client receives as <c>sub</c>: stable for the life of the
    /// account and never reassigned (OpenID Connect Core §2).
    /// </param>
    /// <param name="authenticationMethod">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values —
    /// <c>SignInAsync(user.Subject, AuthenticationMethods.Password)</c> — or pass your own string
    /// for a method the registry does not name. A sign-in that used several takes the overload
    /// with a list.
    /// </param>
    /// <param name="additionalClaims">
    /// Claims held on the SSO session alongside the subject. Held on the session only: tokens and
    /// userinfo get their claims from <c>IClaimsProvider</c>, never from here. A <c>sub</c> or
    /// <see cref="ClaimTypes.NameIdentifier"/> claim is refused, and claims in the reserved
    /// <c>zkd:</c> namespace are stripped.
    /// </param>
    /// <remarks>
    /// Exactly the overload taking a list of methods, with one method in it.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="additionalClaims"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> or <paramref name="authenticationMethod"/> is null or blank, or
    /// an entry in <paramref name="additionalClaims"/> is null or names the subject.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c> — only the login form's submission may sign in, and that
    /// is checked before anything is read — or there is no active HTTP request.
    /// </exception>
    public Task SignInAsync(string subject, string authenticationMethod, params Claim[] additionalClaims)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationMethod);

        return SignInAsync(subject, [authenticationMethod], additionalClaims);
    }

    /// <summary>
    /// Establishes the SSO session for <paramref name="subject"/> and continues the authorization
    /// request that led here.
    /// </summary>
    /// <param name="subject">
    /// The user's identifier, which the client receives as <c>sub</c>: stable for the life of the
    /// account and never reassigned (OpenID Connect Core §2).
    /// </param>
    /// <param name="authenticationMethods">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values, or pass your own string for a
    /// method the registry does not name. RFC 8176 §2 asks that a multi-factor sign-in report
    /// <c>MultiFactor</c> alongside the individual factors:
    /// <c>SignInAsync(user.Subject, [AuthenticationMethods.MultiFactor, AuthenticationMethods.Password, AuthenticationMethods.OneTimePassword])</c>.
    /// </param>
    /// <param name="additionalClaims">
    /// Claims held on the SSO session alongside the subject. Held on the session only: tokens and
    /// userinfo get their claims from <c>IClaimsProvider</c>, never from here. A <c>sub</c> or
    /// <see cref="ClaimTypes.NameIdentifier"/> claim is refused, and claims in the reserved
    /// <c>zkd:</c> namespace are stripped.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. A Razor Pages handler or controller action can simply end after it:
    /// the framework skips MVC's result, including one the handler returns. Anywhere else,
    /// returning a result of your own after calling it throws, because the response has already
    /// started.
    /// </para>
    /// <para>
    /// The arguments are copied when the call is made: what was validated is what is signed in,
    /// whatever the page does to them afterwards.
    /// </para>
    /// <para>
    /// A principal an external provider parked for this interaction — one the host's page did
    /// not finish with — is discarded: the session holds <paramref name="subject"/>, and a local
    /// sign-in records no provider.
    /// </para>
    /// <para>
    /// An empty list omits the <c>amr</c> claim rather than assuming a password. The claim is
    /// optional in OpenID Connect, and a relying party may gate a sensitive operation on what it
    /// says — so the framework states nothing about a sign-in it was told nothing about, instead
    /// of guessing a method that may not be the one used.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="authenticationMethods"/> or <paramref name="additionalClaims"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> or an entry in <paramref name="authenticationMethods"/> is null
    /// or blank, or an entry in <paramref name="additionalClaims"/> is null or names the subject.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c> — only the login form's submission may sign in, and that
    /// is checked before anything is read — or there is no active HTTP request.
    /// </exception>
    public async Task SignInAsync(string subject, IEnumerable<string> authenticationMethods, params Claim[] additionalClaims)
    {
        var methods = SessionPrincipal.Methods(authenticationMethods);
        var user = SessionPrincipal.Build(subject, additionalClaims);

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);

            // A principal an external provider parked for this interaction is discarded, not
            // adopted: the login page signs in the host's own user, and a local sign-in records
            // no provider.
            await _services.Flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false);
            await _services.Outcomes.CompleteSignInAsync(context, requestContext, new SignIn(user, methods, ProviderScheme: null))
                .ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Cancel button.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. A Razor Pages handler or controller action can simply end after it:
    /// the framework skips MVC's result, including one the handler returns. Anywhere else,
    /// returning a result of your own after calling it throws, because the response has already
    /// started.
    /// </para>
    /// <para>
    /// No SSO session is established, and an existing one is left alone — cancelling one client's
    /// request does not sign the user out of another's. The interaction is discarded, so the
    /// cancelled request cannot afterwards be resumed.
    /// </para>
    /// <para>
    /// The client receives an <c>error_description</c> stating that the user cancelled at the
    /// sign-in page and, when it registered with <c>EnableZkdErrorCodes</c>, the <c>zkd_error</c>
    /// <c>login_cancelled</c>, so it can tell this apart from the other refusals that also answer
    /// <c>access_denied</c>.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A cancel wired to a <c>GET</c> anchor would be triggerable cross-site by
    /// anyone who learned the interaction identifier, ending the user's in-flight sign-in.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// the client was told nothing.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task DenyAsync()
    {
        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);
            await _services.Outcomes.DenyAsync(context, requestContext, Denial.CancelledAtSignIn).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends the user out to one of the external providers in <see cref="LoginRequest.Providers"/> to be
    /// authenticated there, and continues the authorization request when they return.
    /// </summary>
    /// <param name="provider">
    /// The <see cref="ProviderDescriptor.Id"/> of the provider the user picked, as the page
    /// received it from <see cref="LoginRequest.Providers"/>.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. A Razor Pages handler or controller action can simply end after it:
    /// the framework skips MVC's result, including one the handler returns. Anywhere else,
    /// returning a result of your own after calling it throws, because the response has already
    /// started.
    /// </para>
    /// <para>
    /// The page names no scheme, callback path or return URL. The framework activates the
    /// provider's handler, serves its callback, and brings the user back to establish the SSO
    /// session — through <c>ProviderOptions.OnProviderSignIn</c> first, when the host registered
    /// one. Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// class remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// <paramref name="provider"/> is not the identifier of a registered provider.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: no challenge was issued.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="provider"/> is null or empty.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task ChallengeAsync(string provider)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);

        // The identifier selects from the configured set; it never names a target. The value is
        // request input, so the message does not echo it. Checked before the interaction is
        // resolved: a wrong identifier is the page's bug, whatever state the interaction is in.
        var context = RequireStateChangingRequest();
        var registration = _providers.Find(provider)
            ?? throw new ZeeKayDaInteractionException(
                "The provider identifier is not one of the registered providers. Pass the Id of an " +
                "entry in LoginRequest.Providers, as the login page received it.");

        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);
            await _services.Outcomes.ChallengeAsync(context, requestContext, registration).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "LoginInteraction requires an active HTTP request. Resolve it from request services " +
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
}
