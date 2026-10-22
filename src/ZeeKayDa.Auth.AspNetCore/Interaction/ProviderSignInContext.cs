using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What <see cref="ProviderOptions.OnProviderSignIn"/> receives: who the user is at the external
/// provider, the principal it authenticated, the provider, the client asking, and the two ways the
/// handler may end the request instead of letting the framework promote the principal.
/// </summary>
/// <remarks>
/// The raw provider ticket is not exposed, and tokens a provider saved into it with
/// <c>SaveTokens</c> are discarded with it when the user returns: nothing here carries a
/// provider's access or refresh token into the session or the parked principal.
/// </remarks>
public sealed class ProviderSignInContext
{
    private readonly Func<PathString, AccountPlacement, Task> _redirect;
    private readonly Func<Task> _deny;
    private int _completed;
    private string? _loginIdentifier;

    internal ProviderSignInContext(
        ExternalIdentity identity,
        ClaimsPrincipal principal,
        ProviderDescriptor provider,
        ClientInformation client,
        IReadOnlyList<string> effectiveScopes,
        CancellationToken requestAborted,
        Func<PathString, AccountPlacement, Task> redirect,
        Func<Task> deny)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(effectiveScopes);
        ArgumentNullException.ThrowIfNull(redirect);
        ArgumentNullException.ThrowIfNull(deny);

        Identity = identity;
        Principal = principal;
        Provider = provider;
        Client = client;
        EffectiveScopes = effectiveScopes;
        RequestAborted = requestAborted;
        _redirect = redirect;
        _deny = deny;
    }

    /// <summary>
    /// Parks <see cref="Principal"/> and sends the user to a page of the host's, to link the
    /// external identity to a local account or to collect what the provider did not supply. That
    /// page reads the principal back with <see cref="ProviderSignInInteraction.GetPendingPrincipalAsync"/>,
    /// keeps anything it collects in the host's own store, and finishes through
    /// <see cref="ProviderSignInInteraction"/>: for the derived subject, or for a linked local
    /// account in its place.
    /// </summary>
    /// <param name="path">
    /// A host-relative path: absolute within the application, starting with <c>/</c>, with no
    /// scheme, authority, query or fragment. The redirect carries the <c>zkd_i</c> query parameter
    /// the page must preserve, as the login page does.
    /// </param>
    /// <remarks>
    /// <strong>Terminal.</strong> This writes and commits the response; it must be the last thing
    /// the handler does, and at most one of this and <see cref="DenyAsync"/> may be called.
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// <paramref name="path"/> is empty, or is not a host-relative path — an absolute or
    /// protocol-relative value, or one carrying a query or fragment.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <see cref="RedirectToAsync"/> or <see cref="DenyAsync"/> has already been called on this
    /// context.
    /// </exception>
    public Task RedirectToAsync(PathString path)
    {
        if (!path.HasValue || !InteractionPath.IsSafe(path.Value))
        {
            throw new ArgumentException(
                "The path must be host-relative: an absolute path within the application, starting " +
                "with '/', with no scheme, authority, query or fragment.",
                nameof(path));
        }

        EnsureFirstTerminalCall();
        return _redirect(path, Placement);
    }

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI.
    /// </summary>
    /// <remarks>
    /// <strong>Terminal.</strong> This writes and commits the response; it must be the last thing
    /// the handler does, and at most one of this and <see cref="RedirectToAsync"/> may be called.
    /// A client registered with <c>EnableZkdErrorCodes</c> also receives the <c>zkd_error</c>
    /// <c>account_refused</c>, to tell this apart from a cancellation at the sign-in page.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// <see cref="RedirectToAsync"/> or <see cref="DenyAsync"/> has already been called on this
    /// context.
    /// </exception>
    public Task DenyAsync()
    {
        EnsureFirstTerminalCall();
        return _deny();
    }

    private void EnsureFirstTerminalCall()
    {
        if (Interlocked.CompareExchange(ref _completed, 1, 0) != 0)
        {
            throw new InvalidOperationException(
                "RedirectToAsync or DenyAsync has already been called on this context. Each is " +
                "terminal: call at most one of them, once.");
        }
    }

    /// <summary>
    /// Who the user is at the provider: the key to find a linked local account by. Read from
    /// <see cref="Principal"/>'s subject claim before this handler runs; a principal without a
    /// usable one is refused, and the handler is never called for it.
    /// </summary>
    public ExternalIdentity Identity { get; }

    /// <summary>
    /// A copy of the principal as the provider returned it, reserved claims removed, for the handler
    /// to read. The session holds none of its claims, only the subject derived from
    /// <see cref="Identity"/>; what the host wants to keep of them belongs in its own store.
    /// </summary>
    public ClaimsPrincipal Principal { get; }

    /// <summary>The provider that authenticated the user.</summary>
    public ProviderDescriptor Provider { get; }

    /// <summary>The client whose authorization request is being completed.</summary>
    public ClientInformation Client { get; }

    /// <summary>The most the request will be granted: the requested scopes the client is allowed.</summary>
    public IReadOnlyList<string> EffectiveScopes { get; }

    /// <summary>
    /// Signalled when the browser disconnects, for a handler that reads a store or provisions an
    /// account before it decides. The same token as <c>HttpContext.RequestAborted</c>.
    /// </summary>
    public CancellationToken RequestAborted { get; }

    /// <summary>
    /// Gets or sets whether the user is signed in beside the accounts this browser already holds,
    /// instead of replacing them. Defaults to <see langword="false"/>: the previous user is signed
    /// out, the safe choice on a shared computer.
    /// </summary>
    /// <remarks>
    /// The host decides here for every external sign-in, whether the framework signs the user in
    /// when the handler returns or a page of the host's finishes it after
    /// <see cref="RedirectToAsync"/>: what is set when that is called goes with the parked principal.
    /// It works as <see cref="LoginInteraction.AddAccountAsync(string, IEnumerable{string}, string, DateTimeOffset?)"/>
    /// does for a local sign-in, cap included.
    /// </remarks>
    public bool AddAccount { get; set; }

    /// <summary>
    /// Gets or sets what the user is known by, such as the email address the provider returned:
    /// shown on the account picker, and matched, ignoring case, against a client's <c>login_hint</c>.
    /// Defaults to <see langword="null"/>, which uses the session subject — a derived subject, 43
    /// characters no user recognises.
    /// </summary>
    /// <remarks>
    /// Held to the rule a <c>login_hint</c> is: at most 256 characters, not blank, with no control,
    /// line-separator or invisible formatting character. A linking page that signs in a local account
    /// in the external user's place can give that account's own identifier instead, through
    /// <see cref="ProviderSignInInteraction.SignInWithReplacedAccountAsync(string, IEnumerable{string}, string, DateTimeOffset?)"/>.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.OnProviderSignIn = context =>
    /// {
    ///     context.AddAccount = true;
    ///     context.LoginIdentifier = context.Principal.FindFirstValue(ClaimTypes.Email);
    ///     return Task.CompletedTask;
    /// };
    /// </code>
    /// </example>
    /// <exception cref="ArgumentException">The value breaks the rule above.</exception>
    public string? LoginIdentifier
    {
        get => _loginIdentifier;
        set => _loginIdentifier = SignInArguments.LoginIdentifier(value);
    }

    /// <summary>Whether a terminal method has been called.</summary>
    internal bool Completed => Volatile.Read(ref _completed) != 0;

    /// <summary>How the host chose to place the account among those the browser holds.</summary>
    internal AccountPlacement Placement => new(LoginIdentifier, AddAccount);
}
