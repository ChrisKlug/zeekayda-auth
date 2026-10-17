using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host login page's completion of an authorization request. The host owns the page, the
/// credential check and the user store; this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page needs no <c>ReturnUrl</c>, scheme name or cookie name. It must preserve the
/// <c>zkd_i</c> query parameter it was reached with, which an ordinary
/// <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// <strong>Terminal methods</strong> — <see cref="SignInAsync(string, IEnumerable{string}, string)"/>,
/// <see cref="AddAccountAsync(string, IEnumerable{string}, string)"/>, <see cref="DenyAsync"/> and
/// <see cref="ChallengeAsync"/> — write and commit the response, so each
/// must be the last thing the page does. A Razor Pages handler or controller action can simply end
/// after it: the framework skips MVC's result. Anywhere else, returning a result of your own
/// afterwards throws, because the response has started. Only a <c>POST</c> is accepted, checked
/// before anything is read: the framework's cookies accompany a cross-site top-level <c>GET</c>, so
/// a step wired to a link could be triggered unseen.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — no <c>zkd_i</c>; the interaction expired, was completed or belongs
/// to another browser; or another response completed it first — the framework sends the browser to
/// the client's <c>InitiateLoginUri</c>, with <c>iss</c>, when it can still say which client it came
/// from, and to the error page with <see cref="AuthorizationErrorKind.NothingToContinue"/> otherwise.
/// A missing <c>zkd_i</c> is also logged as a warning, since a form that drops it fails on every
/// submission.
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
    /// The page takes credentials, so the response is marked unframeable (<c>Content-Security-Policy:
    /// frame-ancestors 'none'</c>, appended to any policy of the host's, and <c>X-Frame-Options:
    /// DENY</c>) and <c>Cache-Control: no-store</c>, before the read.
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

        RenderedPage.Protect(context.Response);
        var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);
        var client = await _services.Flow.DescribeClientAsync(context, requestContext, cancellationToken).ConfigureAwait(false);
        var sessions = await _services.Flow.ReadSessionsAsync(context).ConfigureAwait(false);
        var session = sessions.Select(requestContext.ClientId, requestContext.RequiredSubject, requestContext.LoginHint);

        return new LoginRequest(
            client,
            _providers.Descriptors,
            _options.Value.AuthorizationEndpoint.Interaction.SupportsLocalSignIn,
            ProviderReturnOf(requestContext.ProviderAttempt),
            requestContext.LoginHint,
            _services.Flow.RequiresReauthentication(requestContext.Prompts, requestContext.MaxAge, session),
            requestContext.RequiredSubject)
        {
            SignedInAccounts = sessions.Accounts.Select(SignedInAccount.Of).ToArray(),
        };
    }

    /// <summary>
    /// What the page should render for, or <see langword="null"/> when there is no interaction to
    /// sign in for — for a page that renders its own "nothing to continue" message.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// Exactly <see cref="GetRequestAsync"/>, headers included, except that each case it reports with
    /// <see cref="ZeeKayDaInteractionException"/> returns <see langword="null"/>. A request with no
    /// <c>zkd_i</c> is logged as a warning.
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

#pragma warning disable RS0026 // An optional login identifier on the one- and many-method overloads; nothing is shipped to stay compatible with.
    /// <summary>
    /// Signs the user in as <paramref name="subject"/>, authenticated by
    /// <paramref name="authenticationMethod"/>, signing out every other account this browser holds,
    /// and continues the authorization request that led here.
    /// </summary>
    /// <param name="subject">
    /// The user's identifier, which the client receives as <c>sub</c>: 1–255 printable ASCII
    /// characters with no space, stable for the life of the account and never reassigned (OpenID
    /// Connect Core §2).
    /// </param>
    /// <param name="authenticationMethod">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values —
    /// <c>SignInAsync(user.Subject, AuthenticationMethods.Password)</c> — or pass your own string
    /// for a method the registry does not name. A sign-in that used several takes the overload
    /// with a list.
    /// </param>
    /// <param name="loginIdentifier">
    /// What the user signs in with, such as an email address: shown on the account picker, and
    /// matched against a client's <c>login_hint</c>. <see langword="null"/> uses
    /// <paramref name="subject"/> for both.
    /// </param>
    /// <remarks>
    /// Exactly the overload taking a list of methods, with one method in it.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="subject"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> is not 1–255 printable ASCII characters with no space,
    /// <paramref name="authenticationMethod"/> is null or blank, or <paramref name="loginIdentifier"/>
    /// breaks the rule <see cref="SignInAsync(string, IEnumerable{string}, string)"/> states.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c> — only the login form's submission may sign in, and that
    /// is checked before anything is read — or there is no active HTTP request.
    /// </exception>
    public Task SignInAsync(string subject, string authenticationMethod, string? loginIdentifier = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationMethod);

        return SignInAsync(subject, [authenticationMethod], loginIdentifier);
    }

    /// <summary>
    /// Signs the user in as <paramref name="subject"/>, signing out every other account this browser
    /// holds, and continues the authorization request that led here.
    /// </summary>
    /// <param name="subject">
    /// The user's identifier, which the client receives as <c>sub</c>: 1–255 printable ASCII
    /// characters with no space, stable for the life of the account and never reassigned (OpenID
    /// Connect Core §2).
    /// </param>
    /// <param name="authenticationMethods">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values, or pass your own string for a
    /// method the registry does not name. RFC 8176 §2 asks that a multi-factor sign-in report
    /// <c>MultiFactor</c> alongside the individual factors:
    /// <c>SignInAsync(user.Subject, [AuthenticationMethods.MultiFactor, AuthenticationMethods.Password, AuthenticationMethods.OneTimePassword])</c>.
    /// </param>
    /// <param name="loginIdentifier">
    /// What the user signs in with, such as an email address: shown on the account picker as
    /// <see cref="SignedInAccount.LoginIdentifier"/>, and matched, ignoring case, against a client's
    /// <c>login_hint</c>. At most 256 characters, not blank, with no control, line-separator or
    /// invisible formatting character — the rule a <c>login_hint</c> is held to.
    /// <see langword="null"/> uses <paramref name="subject"/> for both, and then only a
    /// <c>login_hint</c> equal to the subject selects this account: a client that sends email
    /// addresses as hints gets the login page every time.
    /// </param>
    /// <remarks>
    /// <para>
    /// Terminal (see the class remarks). The arguments are copied when the call is made, so what was
    /// validated is what is signed in. A principal an external provider parked for this interaction
    /// is discarded: a local sign-in records no provider.
    /// </para>
    /// <para>
    /// This replaces the accounts the browser holds, which is the safe default on a shared computer:
    /// the previous user is signed out. <see cref="AddAccountAsync(string, IEnumerable{string}, string)"/>
    /// keeps them instead. Signing in again as an account the browser holds keeps its session
    /// identifier either way.
    /// </para>
    /// <para>
    /// An empty list omits the <c>amr</c> claim rather than assuming a password: a relying party may
    /// gate a sensitive operation on it, so the framework states nothing it was not told.
    /// </para>
    /// <para>
    /// When <see cref="LoginRequest.ReauthenticationRequired"/> is <see langword="true"/>, call this
    /// only after the user has actively authenticated on the page: a cookie of the host's own is not
    /// enough (OpenID Connect Core §3.1.2.3).
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="subject"/> or <paramref name="authenticationMethods"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> is not 1–255 printable ASCII characters with no space, an entry
    /// in <paramref name="authenticationMethods"/> is null or blank, or
    /// <paramref name="loginIdentifier"/> breaks the rule above.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c> — only the login form's submission may sign in, and that
    /// is checked before anything is read — or there is no active HTTP request.
    /// </exception>
    public Task SignInAsync(string subject, IEnumerable<string> authenticationMethods, string? loginIdentifier = null) =>
        CompleteAsync(SignInArguments.Local(subject, authenticationMethods, loginIdentifier, addAccount: false));

    /// <summary>
    /// Signs the user in as <paramref name="subject"/>, authenticated by
    /// <paramref name="authenticationMethod"/>, beside the accounts this browser already holds, and
    /// continues the authorization request that led here.
    /// </summary>
    /// <param name="subject">The user's identifier, on the terms <see cref="SignInAsync(string, IEnumerable{string}, string)"/> states.</param>
    /// <param name="authenticationMethod">
    /// How the user proved who they are, on the terms <see cref="SignInAsync(string, string, string)"/> states.
    /// </param>
    /// <param name="loginIdentifier">
    /// What the user signs in with, on the terms <see cref="SignInAsync(string, IEnumerable{string}, string)"/> states.
    /// </param>
    /// <remarks>
    /// Exactly the overload taking a list of methods, with one method in it.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="subject"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/>, <paramref name="authenticationMethod"/> or
    /// <paramref name="loginIdentifier"/> breaks the rule <see cref="SignInAsync(string, string, string)"/> states.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    public Task AddAccountAsync(string subject, string authenticationMethod, string? loginIdentifier = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationMethod);

        return AddAccountAsync(subject, [authenticationMethod], loginIdentifier);
    }

    /// <summary>
    /// Signs the user in as <paramref name="subject"/> beside the accounts this browser already
    /// holds, and continues the authorization request that led here.
    /// </summary>
    /// <param name="subject">The user's identifier, on the terms <see cref="SignInAsync(string, IEnumerable{string}, string)"/> states.</param>
    /// <param name="authenticationMethods">
    /// How the user proved who they are, on the terms <see cref="SignInAsync(string, IEnumerable{string}, string)"/> states.
    /// </param>
    /// <param name="loginIdentifier">
    /// What the user signs in with, on the terms <see cref="SignInAsync(string, IEnumerable{string}, string)"/>
    /// states. Give one: it is what the account picker shows the user for this account.
    /// </param>
    /// <remarks>
    /// <para>
    /// Exactly <see cref="SignInAsync(string, IEnumerable{string}, string)"/>, except that the other
    /// accounts stay signed in. The page decides when to add: it may ask the user ("keep
    /// alice@contoso.com signed in?"), or always add on a host whose devices are personal. On a
    /// shared computer, adding leaves the previous user signed in and selectable on the account
    /// picker without a password.
    /// </para>
    /// <para>
    /// The new account becomes the one this client is answered for, and the most recently used. A
    /// browser holds at most <c>AuthorizationEndpoint.Interaction.MaxSignedInAccounts</c> accounts;
    /// adding one more signs out the account least recently signed in to or chosen.
    /// </para>
    /// <example>
    /// A login page that lets the user choose:
    /// <code>
    /// if (keepOthersSignedIn)
    ///     await login.AddAccountAsync(user.Subject, AuthenticationMethods.Password, user.Email);
    /// else
    ///     await login.SignInAsync(user.Subject, AuthenticationMethods.Password, user.Email);
    /// </code>
    /// </example>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="subject"/> or <paramref name="authenticationMethods"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/>, an entry in <paramref name="authenticationMethods"/>, or
    /// <paramref name="loginIdentifier"/> breaks the rule <see cref="SignInAsync(string, IEnumerable{string}, string)"/> states.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    public Task AddAccountAsync(string subject, IEnumerable<string> authenticationMethods, string? loginIdentifier = null) =>
        CompleteAsync(SignInArguments.Local(subject, authenticationMethods, loginIdentifier, addAccount: true));
#pragma warning restore RS0026

    /// <summary>Signs in what the arguments, already checked, describe.</summary>
    private Task CompleteAsync(SignIn signIn) =>
        StepAsync(async (context, requestContext) =>
        {
            await _services.Flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false);
            await _services.Outcomes.CompleteSignInAsync(context, requestContext, signIn).ConfigureAwait(false);
        });

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Cancel button.
    /// </summary>
    /// <remarks>
    /// Terminal (see the class remarks). No SSO session is established, and an existing one is left
    /// alone: cancelling one client's request does not sign the user out of another's. The
    /// interaction is discarded. A client registered with <c>EnableZkdErrorCodes</c> also receives
    /// the <c>zkd_error</c> <c>login_cancelled</c>, to tell this apart from other
    /// <c>access_denied</c> refusals.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// the client was told nothing.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public Task DenyAsync() =>
        StepAsync((context, requestContext) => _services.Outcomes.DenyAsync(context, requestContext, Denial.CancelledAtSignIn));

    /// <summary>
    /// Runs a terminal step for the addressed interaction, from the login form's post only; with
    /// nothing to continue, the framework answers instead.
    /// </summary>
    private async Task StepAsync(Func<HttpContext, AuthorizationRequestContext, Task> step)
    {
        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);
            await step(context, requestContext).ConfigureAwait(false);
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
    /// Terminal (see the class remarks). The framework activates the provider's handler, serves its
    /// callback, and brings the user back to establish the SSO session — through
    /// <c>ProviderOptions.OnProviderSignIn</c> first, when the host registered one.
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

        // Request input, so the message does not echo it.
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

    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "A sign-in, cancellation or provider choice must come from a POST — the login form's " +
                "submission — not from the request that renders the page. Wire SignInAsync, " +
                "AddAccountAsync, DenyAsync and ChallengeAsync to the form's post handlers.");
        }

        return context;
    }
}
