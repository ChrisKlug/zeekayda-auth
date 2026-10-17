using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host account picker's completion of an authorization request, at
/// <c>AuthorizationEndpoint.Interaction.SelectAccountPath</c>. The host owns the page; this service
/// owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// A client asks for the picker with <c>prompt=select_account</c> (OpenID Connect Core §3.1.2.1),
/// and the framework sends the browser here only when at least one account it holds could answer
/// the request without signing in again. The user picks one of
/// <see cref="AccountSelectionRequest.Accounts"/> — no credentials, since the browser is already
/// signed in to it — or goes on to the login page to sign in as someone else.
/// </para>
/// <para>
/// The page must preserve the <c>zkd_i</c> query parameter it was reached with, which an ordinary
/// <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// <strong>Terminal methods</strong> — <see cref="SelectAsync"/>, <see cref="UseAnotherAccountAsync"/>
/// and <see cref="DenyAsync"/> — write and commit the response, so each must be the last thing the
/// page does. A Razor Pages handler or controller action can simply end after it: the framework
/// skips MVC's result. Anywhere else, returning a result of your own afterwards throws, because the
/// response has started. Only a <c>POST</c> is accepted, checked before anything is read: the
/// framework's cookies accompany a cross-site top-level <c>GET</c>, so a step wired to a link could
/// be triggered unseen.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — no <c>zkd_i</c>; the interaction expired, was completed, belongs
/// to another browser, or never asked for an account choice; or another response completed it first
/// — the framework sends the browser to the client's <c>InitiateLoginUri</c>, with <c>iss</c>, when it
/// can still say which client it came from, and to the error page with
/// <see cref="AuthorizationErrorKind.NothingToContinue"/> otherwise.
/// </para>
/// </remarks>
/// <example>
/// A Razor Pages picker:
/// <code>
/// public sealed class SelectAccountModel(AccountSelectionInteraction picker) : PageModel
/// {
///     public AccountSelectionRequest? Request { get; private set; }
///
///     public async Task OnGetAsync() =>
///         Request = await picker.TryGetRequestAsync(HttpContext.RequestAborted);
///
///     public async Task OnPostAsync(string? account, string? action)
///     {
///         if (action == "cancel")
///             await picker.DenyAsync();
///         else if (account is null)
///             await picker.UseAnotherAccountAsync();
///         else
///             await picker.SelectAsync(account);
///     }
/// }
/// </code>
/// with a form that posts one button per account — <c>&lt;button name="account" value="@a.Subject"&gt;@a.LoginIdentifier&lt;/button&gt;</c> —
/// and a "Use another account" button with no <c>account</c> value.
/// </example>
public sealed class AccountSelectionInteraction
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly PageInteractionServices _services;

    internal AccountSelectionInteraction(
        IHttpContextAccessor httpContextAccessor,
        PageInteractionServices services)
    {
        _httpContextAccessor = httpContextAccessor;
        _services = services;
    }

    private const string Page = "account selection";

    /// <summary>What the page should offer: the client, and the accounts the user may continue as.</summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// The page takes a one-click decision, so the response is marked unframeable
    /// (<c>Content-Security-Policy: frame-ancestors 'none'</c>, appended to any policy of the host's,
    /// and <c>X-Frame-Options: DENY</c>) and <c>Cache-Control: no-store</c>, before the read.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no account choice to offer: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, or was started
    /// in another browser — or one that never asked for an account choice. A page that wants to
    /// render its own message for these cases calls <see cref="TryGetRequestAsync"/> instead.
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
    public async Task<AccountSelectionRequest> GetRequestAsync(CancellationToken cancellationToken = default)
    {
        var context = RequireHttpContext();

        cancellationToken.ThrowIfCancellationRequested();

        RenderedPage.Protect(context.Response);
        var requestContext = await ResolveAsync(context).ConfigureAwait(false);
        var client = await _services.Flow.DescribeClientAsync(context, requestContext, cancellationToken).ConfigureAwait(false);
        var selectable = await SelectableAsync(context, requestContext).ConfigureAwait(false);

        return new AccountSelectionRequest(client, selectable.Accounts.Select(SignedInAccount.Of).ToArray());
    }

    /// <summary>
    /// What the page should offer, or <see langword="null"/> when there is no account choice to
    /// offer — for a page that renders its own "nothing to continue" message.
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
    public async Task<AccountSelectionRequest?> TryGetRequestAsync(CancellationToken cancellationToken = default)
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

    /// <summary>
    /// Continues the authorization request as the account the user picked, and makes it the one this
    /// client is answered for from now on. This is an account's button on the picker.
    /// </summary>
    /// <param name="subject">
    /// The <see cref="SignedInAccount.Subject"/> of the account the user picked, as the page received
    /// it in <see cref="AccountSelectionRequest.Accounts"/>.
    /// </param>
    /// <remarks>
    /// Terminal (see the class remarks). No credentials are asked for: the browser is already signed
    /// in to the account. The account must still be one the request would accept, checked against
    /// the session cookie when the form is posted — a value the browser does not hold, or one signed
    /// out since the page rendered, is refused, whatever the form carried.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// <paramref name="subject"/> is not one of the accounts the request may continue as.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was issued.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="subject"/> is null or empty.</exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task SelectAsync(string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var requestContext = await ResolveAsync(context).ConfigureAwait(false);
            var (sessions, accounts) = await SelectableAsync(context, requestContext).ConfigureAwait(false);

            // Request input, so the message does not echo it.
            var account = accounts.FirstOrDefault(candidate => string.Equals(candidate.Subject, subject, StringComparison.Ordinal))
                ?? throw new ZeeKayDaInteractionException(
                    "The account is not one this request may continue as: it is not signed in to this " +
                    "browser, was signed out since the page rendered, or is ruled out by the request. Pass " +
                    "the Subject of an entry in AccountSelectionRequest.Accounts.");

            await _services.Outcomes.CompleteSelectionAsync(context, requestContext, sessions, account).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends the user on to sign in as an account the picker does not show, and continues the
    /// authorization request from there. This is the "Use another account" button.
    /// </summary>
    /// <remarks>
    /// Terminal (see the class remarks). The user goes to the login page, or straight to the one
    /// external provider when the host has no login page to choose on. Whether the new account joins
    /// those the browser holds is decided where it signs in, as for any sign-in.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: the user was sent nowhere.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    public async Task UseAnotherAccountAsync()
    {
        var context = RequireStateChangingRequest();
        await _services.NothingToContinue.SignInStepAsync(context, Page, async () =>
        {
            var requestContext = await ResolveAsync(context).ConfigureAwait(false);
            var result = await _services.Outcomes.AuthenticateAsync(context, requestContext).ConfigureAwait(false);
            await InteractionOutcomes.EndWithAsync(context, result).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Ends the authorization request without continuing as anyone, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Cancel button.
    /// </summary>
    /// <remarks>
    /// Terminal (see the class remarks). Every account stays signed in. A client registered with
    /// <c>EnableZkdErrorCodes</c> also receives the <c>zkd_error</c> <c>login_cancelled</c>, as for a
    /// cancellation on the login page.
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
            var requestContext = await ResolveAsync(context).ConfigureAwait(false);
            await _services.Outcomes.DenyAsync(context, requestContext, Denial.CancelledAtSignIn).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    /// <summary>The addressed interaction, if it asked for an account choice.</summary>
    private async ValueTask<AuthorizationRequestContext> ResolveAsync(HttpContext context)
    {
        var requestContext = await _services.Flow.ResolveAddressedAsync(context).ConfigureAwait(false);
        if (requestContext.Prompts.Contains(PromptValue.SelectAccount))
            return requestContext;

        throw new NothingToContinueException(
            NothingToContinueReason.NotAccountSelection,
            "This authorization request did not ask for an account choice (prompt=select_account), so the " +
            "account picker has nothing to offer for it. The framework sends the browser to the picker only " +
            "for a request that asks.");
    }

    /// <summary>The accounts the browser holds, and those of them the request may continue as.</summary>
    private async ValueTask<(SsoSessionList Sessions, IReadOnlyList<SsoSessionState> Accounts)> SelectableAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext)
    {
        var sessions = await _services.Flow.ReadSessionsAsync(context).ConfigureAwait(false);
        var accounts = _services.Flow.SelectableAccounts(requestContext.Prompts, requestContext.MaxAge, requestContext.RequiredSubject, sessions);

        return (sessions, accounts);
    }

    private HttpContext RequireHttpContext() =>
        _httpContextAccessor.HttpContext ?? throw new InvalidOperationException(
            "AccountSelectionInteraction requires an active HTTP request. Resolve it from request services " +
            "inside the account picker, not from a background service.");

    private HttpContext RequireStateChangingRequest()
    {
        var context = RequireHttpContext();

        if (!HttpMethods.IsPost(context.Request.Method))
        {
            throw new InvalidOperationException(
                "An account choice must come from a POST — the picker form's submission — not from the " +
                "request that renders the page. Wire SelectAsync, UseAnotherAccountAsync and DenyAsync to " +
                "the form's post handlers.");
        }

        return context;
    }
}
