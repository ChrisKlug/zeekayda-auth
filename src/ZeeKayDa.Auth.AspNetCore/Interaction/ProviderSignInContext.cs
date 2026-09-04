using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What <see cref="ProviderOptions.OnProviderSignIn"/> receives: the principal an external
/// provider authenticated, the provider, the client asking, and the two ways the handler may end
/// the request instead of letting the framework promote the principal.
/// </summary>
/// <remarks>
/// The raw provider ticket is not exposed, and tokens a provider saved into it with
/// <c>SaveTokens</c> are discarded with it when the user returns: nothing here carries a
/// provider's access or refresh token into the session or the parked principal.
/// </remarks>
public sealed class ProviderSignInContext
{
    private readonly Func<PathString, Task> _redirect;
    private readonly Func<Task> _deny;
    private int _completed;

    internal ProviderSignInContext(
        ClaimsPrincipal principal,
        ProviderDescriptor provider,
        ClientInformation client,
        IReadOnlyList<string> effectiveScopes,
        CancellationToken requestAborted,
        Func<PathString, Task> redirect,
        Func<Task> deny)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(effectiveScopes);
        ArgumentNullException.ThrowIfNull(redirect);
        ArgumentNullException.ThrowIfNull(deny);

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
    /// page reads the principal back with <see cref="ILoginInteraction.GetPendingPrincipalAsync"/>
    /// and finishes with <see cref="ILoginInteraction.SignInAsync"/>.
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

        Claim();
        return _redirect(path);
    }

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI.
    /// </summary>
    /// <remarks>
    /// <strong>Terminal.</strong> This writes and commits the response; it must be the last thing
    /// the handler does, and at most one of this and <see cref="RedirectToAsync"/> may be called.
    /// The client receives an <c>error_description</c> naming a refusal after sign-in at the
    /// external provider, so it can tell this apart from a cancellation at the sign-in page.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// <see cref="RedirectToAsync"/> or <see cref="DenyAsync"/> has already been called on this
    /// context.
    /// </exception>
    public Task DenyAsync()
    {
        Claim();
        return _deny();
    }

    /// <summary>
    /// Terminal means once. Enforced structurally rather than by the current call graph, so a
    /// handler that calls both, or one of them twice, fails the first time it runs.
    /// </summary>
    private void Claim()
    {
        if (Interlocked.CompareExchange(ref _completed, 1, 0) != 0)
        {
            throw new InvalidOperationException(
                "RedirectToAsync or DenyAsync has already been called on this context. Each is " +
                "terminal: call at most one of them, once.");
        }
    }

    /// <summary>
    /// The principal as the provider returned it, with the framework's reserved claims removed.
    /// A copy: what the framework parks or promotes is its own, so a change made here is not
    /// carried into the session. A host that wants the session to hold something else redirects
    /// to a page of its own and passes that principal to <c>SignInAsync</c>.
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

    /// <summary>Whether a terminal method has been called.</summary>
    internal bool Completed => Volatile.Read(ref _completed) != 0;
}
