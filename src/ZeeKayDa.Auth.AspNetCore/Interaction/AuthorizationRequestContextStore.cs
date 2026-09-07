using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;
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
/// browser at once. The one bound is on what an unauthenticated request may make the store hold:
/// a context whose encoding exceeds <c>AuthorizationEndpoint.MaxRequestContextBytes</c> is
/// refused before anything is written.
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
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISanitizingLogger<AuthorizationRequestContextStore> _logger;

    public AuthorizationRequestContextStore(
        IInteractionBackingStore store,
        InteractionBindingCookie binding,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<AuthorizationServerOptions> options,
        TimeProvider timeProvider,
        ISanitizingLogger<AuthorizationRequestContextStore> logger)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _store = store;
        _binding = binding;
        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// Stores a freshly accepted request and binds it to this browser with a new binding cookie.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the encoded context exceeds
    /// <c>AuthorizationEndpoint.MaxRequestContextBytes</c>, in which case nothing is written, no
    /// cookie is issued, and the caller must answer <c>invalid_request</c>.
    /// </returns>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the write.</exception>
    public async ValueTask<bool> TryStoreAsync(HttpContext context, AuthorizationRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var encoded = AuthorizationRequestContextSerializer.Encode(requestContext);
        if (encoded.Length > _options.Value.AuthorizationEndpoint.MaxRequestContextBytes)
            return false;

        // The entry first, the cookie second: a write the store refused leaves the browser with no
        // binding to a nothing, and evicts no other tab's binding for it.
        var secret = InteractionBindingCookie.NewSecret();
        await SetAsync(requestContext, secret, encoded, cancellationToken).ConfigureAwait(false);
        _binding.Issue(context, requestContext.Id, requestContext.ExpiresAt, secret);

        return true;
    }

    /// <summary>
    /// Replaces a stored context in place — the sign-in adding the authenticated session — under
    /// the binding the request carries. Not size-guarded: the request was accepted under the cap,
    /// and what an authenticated sign-in adds is small and bounded.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The request carries no binding for this interaction. Every caller reads the context first,
    /// so the binding is present; a rewrite without one would otherwise become an unbound copy.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the write.</exception>
    public async ValueTask UpdateAsync(HttpContext context, AuthorizationRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var secret = _binding.Read(context, requestContext.Id)
            ?? throw new InvalidOperationException(
                "The interaction context cannot be updated from a request that carries no binding for it. " +
                "Read the context first; a rewrite is only ever of a context this browser holds.");

        await SetAsync(requestContext, secret, AuthorizationRequestContextSerializer.Encode(requestContext), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SetAsync(AuthorizationRequestContext requestContext, string secret, byte[] encoded, CancellationToken cancellationToken)
    {
        var protectedValue = _protector.Protect(encoded);

        await Guarded(
            () => _store.SetAsync(KeyFor(requestContext.Id, secret), protectedValue, requestContext.ExpiresAt, cancellationToken),
            "store the interaction context").ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the context for <paramref name="interactionId"/>. Returns <see langword="null"/> when
    /// this browser holds no binding for it, when there is no entry, when the entry has expired,
    /// when it is protected under a key this application cannot read, or when it names another
    /// interaction — never throws for a value it cannot make sense of.
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

        // Data Protection authenticates the bytes, not which row they sit in. Whoever can write to
        // the store without holding the keys could still move one interaction's valid ciphertext
        // under another's key; the identifier inside the payload is what ties the two together.
        if (!InteractionHandoff.IdentifiersMatch(requestContext!.Id, interactionId))
            return null;

        // The expiry inside the payload is authoritative, not the store's TTL or the cookie's
        // MaxAge: neither of those is checked by anything this framework controls.
        return _timeProvider.GetUtcNow() >= requestContext.ExpiresAt ? null : requestContext;
    }

    /// <summary>
    /// Discards the interaction: the binding cookie, and the entry when this browser can address
    /// it. Called when the flow terminates — the code is issued, consent is denied, or the request
    /// errors out. Best-effort by construction: the cookie goes first and cannot fail, and a store
    /// that refuses the removal is logged rather than thrown, since the browser has already lost
    /// the only thing that could address the entry, which is left to its lifetime.
    /// </summary>
    /// <remarks>
    /// Every caller is ending a request — with a code already stored, an error already decided, or
    /// a denial — and none of those outcomes should be replaced by a failure to tidy up.
    /// </remarks>
    public async ValueTask DeleteAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var secret = _binding.Read(context, interactionId);
        _binding.Delete(context, interactionId);

        if (secret is null)
            return;

        try
        {
            await Guarded(
                () => _store.RemoveAsync(KeyFor(interactionId, secret), cancellationToken),
                "remove the interaction context").ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            _logger.LogError(ex, "Removing a completed interaction from the store failed; the entry is left to expire.");
        }
    }

    private static StoreKey KeyFor(string interactionId, string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Concat(interactionId, ".", secret)));
        return new StoreKey($"zkd:interaction:c:{Convert.ToHexStringLower(hash)}");
    }
}
