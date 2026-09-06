using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Keeps the <see cref="AuthorizationRequestContext"/> between the redirects of the authorize
/// flow: an encrypted entry in the interaction store, keyed by the interaction identifier and the
/// secret in that interaction's binding cookie, so that only the browser that started a request
/// can read, rewrite or discard it.
/// </summary>
/// <remarks>
/// <para>
/// Each interaction is its own entry and its own cookie, so any number can be in flight in one
/// browser at once, and the payload has no size ceiling: a <c>state</c> the client made large is
/// the store's problem, not a header's.
/// </para>
/// <para>
/// The store never holds the identifier or the secret, only a hash of the pair, and the bytes it
/// holds are protected on the host's key ring. A copy of the store alone cannot be used to act on
/// an interaction, and cannot be read.
/// </para>
/// </remarks>
internal sealed class AuthorizationRequestContextStore
{
    /// <summary>
    /// The hard lifetime of an interaction. Not sliding: a request gets one window to complete,
    /// not a renewable one.
    /// </summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(30);

    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizationRequestContext";

    private readonly IInteractionBackingStore _store;
    private readonly InteractionBindingCookie _binding;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

    public AuthorizationRequestContextStore(
        IInteractionBackingStore store,
        InteractionBindingCookie binding,
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _store = store;
        _binding = binding;
        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Stores the context, binding it to this browser. A first write issues the binding cookie; a
    /// rewrite — the sign-in adding the authenticated session — reuses the one the request
    /// carries, so the entry is replaced in place.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the write.</exception>
    public async ValueTask WriteAsync(HttpContext context, AuthorizationRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var secret = _binding.Read(context, requestContext.Id)
            ?? _binding.Issue(context, requestContext.Id, requestContext.ExpiresAt);

        var protectedValue = _protector.Protect(AuthorizationRequestContextSerializer.Encode(requestContext));

        await Guarded(
            () => _store.SetAsync(KeyFor(requestContext.Id, secret), protectedValue, requestContext.ExpiresAt, cancellationToken),
            "store the interaction context").ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the context for <paramref name="interactionId"/>. Returns <see langword="null"/> when
    /// this browser holds no binding for it, when there is no entry, when the entry has expired,
    /// or when it is protected under a key this application cannot read — never throws for a
    /// value it cannot make sense of.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<AuthorizationRequestContext?> ReadAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (_binding.Read(context, interactionId) is not { } secret)
            return null;

        var stored = await Guarded(
            () => _store.GetAsync(KeyFor(interactionId, secret), cancellationToken),
            "read the interaction context").ConfigureAwait(false);

        if (stored is null)
            return null;

        byte[] payload;
        try
        {
            payload = _protector.Unprotect(stored.Value.ToArray());
        }
        catch (CryptographicException)
        {
            return null;
        }

        if (!AuthorizationRequestContextSerializer.TryDecode(payload, out var requestContext))
            return null;

        // The expiry inside the payload is authoritative, not the store's TTL or the cookie's
        // MaxAge: neither of those is checked by anything this framework controls.
        return _timeProvider.GetUtcNow() >= requestContext!.ExpiresAt ? null : requestContext;
    }

    /// <summary>
    /// Discards the interaction: the binding cookie, and the entry when this browser can address
    /// it. Called when the flow terminates — the code is issued, consent is denied, or the request
    /// errors out.
    /// </summary>
    /// <remarks>
    /// The cookie goes first and cannot fail. Should the store then refuse the removal, the browser
    /// has already lost the only thing that could address the entry, which is left to its TTL.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the removal.</exception>
    public async ValueTask DeleteAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var secret = _binding.Read(context, interactionId);
        _binding.Delete(context, interactionId);

        if (secret is not null)
        {
            await Guarded(
                () => _store.RemoveAsync(KeyFor(interactionId, secret), cancellationToken),
                "remove the interaction context").ConfigureAwait(false);
        }
    }

    private static StoreKey KeyFor(string interactionId, string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Concat(interactionId, ".", secret)));
        return new StoreKey($"zkd:interaction:c:{Convert.ToHexStringLower(hash)}");
    }
}
