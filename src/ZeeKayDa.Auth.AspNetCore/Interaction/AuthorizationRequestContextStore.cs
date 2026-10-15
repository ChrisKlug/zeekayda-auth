using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Stores;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Keeps the <see cref="AuthorizationRequestContext"/> between the authorize flow's redirects,
/// readable only by the browser that holds the interaction's binding cookie.
/// </summary>
/// <remarks>
/// Keyed by a hash of the identifier and binding secret, and sealed under a purpose derived from
/// the pair: a copy of the store can neither read an entry nor move one under a secret of its own.
/// </remarks>
internal sealed class AuthorizationRequestContextStore(
    IInteractionBackingStore store,
    InteractionBindingCookie binding,
    IDataProtectionProvider dataProtectionProvider,
    TimeProvider timeProvider,
    SanitizingLogger<AuthorizationRequestContextStore> logger)
{
    /// <summary>The hard, non-sliding lifetime of an interaction.</summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(30);

    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizationRequestContext";

    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);

    /// <summary>
    /// Stores a new request under a new binding cookie; <see langword="false"/>, writing nothing,
    /// when its encoding exceeds <paramref name="maxEncodedBytes"/>.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the write.</exception>
    public async ValueTask<bool> TryStoreAsync(HttpContext context, AuthorizationRequestContext requestContext, int maxEncodedBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var encoded = AuthorizationRequestContextSerializer.Encode(requestContext);
        if (encoded.Length > maxEncodedBytes)
            return false;

        // Entry before cookie: a refused write must not evict another tab's binding.
        var secret = InteractionBindingCookie.NewSecret();
        await SetAsync(requestContext, secret, encoded, cancellationToken).ConfigureAwait(false);
        binding.Issue(context, new(requestContext.Id, requestContext.ExpiresAt, secret, requestContext.ClientId));

        return true;
    }

    /// <summary>
    /// Replaces a stored context in place under the request's binding. Not size-guarded: what a
    /// sign-in adds to an accepted request is small and bounded.
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

        var secret = binding.Read(context, requestContext.Id)
            ?? throw new InvalidOperationException(
                "The interaction context cannot be updated from a request that carries no binding for it. " +
                "Read the context first; a rewrite is only ever of a context this browser holds.");

        await SetAsync(requestContext, secret, AuthorizationRequestContextSerializer.Encode(requestContext), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SetAsync(AuthorizationRequestContext requestContext, string secret, byte[] encoded, CancellationToken cancellationToken)
    {
        var protectedValue = ProtectorFor(requestContext.Id, secret).Protect(encoded);

        await Guarded(
            () => store.SetAsync(KeyFor(requestContext.Id, secret), protectedValue, requestContext.ExpiresAt, cancellationToken),
            "store the interaction context").ConfigureAwait(false);
    }

    /// <summary>The context bound to <paramref name="interactionId"/>; anything unreadable is <see langword="null"/>.</summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<AuthorizationRequestContext?> ReadAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (binding.Read(context, interactionId) is not { } secret)
            return null;

        var stored = await Guarded(
            () => store.GetAsync(KeyFor(interactionId, secret), cancellationToken),
            "read the interaction context").ConfigureAwait(false);

        if (stored is null)
            return null;

        byte[] payload;
        try
        {
            payload = ProtectorFor(interactionId, secret).Unprotect(stored.Value.ToArray());
        }
        catch (CryptographicException)
        {
            return null;
        }

        if (!AuthorizationRequestContextSerializer.TryDecode(payload, out var requestContext))
            return null;

        // Neither the sealing purpose nor the store's TTL is trusted alone.
        return InteractionHandoff.IdentifiersMatch(requestContext!.Id, interactionId) && !IsExpired(requestContext)
            ? requestContext
            : null;
    }

    /// <summary>
    /// Retires the binding cookie, then removes the entry best-effort: the browser can no longer
    /// address it, and the request's outcome must not be replaced by a failure to tidy up.
    /// </summary>
    public async ValueTask DeleteAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var secret = binding.Read(context, interactionId);
        binding.Retire(context, interactionId);

        if (secret is null)
            return;

        try
        {
            await Guarded(
                () => store.RemoveAsync(KeyFor(interactionId, secret), cancellationToken),
                "remove the interaction context").ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            logger.LogError(ex, "Removing a completed interaction from the store failed; the entry is left to expire.");
        }
    }

    private bool IsExpired(AuthorizationRequestContext requestContext) => timeProvider.GetUtcNow() >= requestContext.ExpiresAt;

    private static StoreKey KeyFor(string interactionId, string secret) => InteractionStoreKeys.Context(interactionId, secret);

    private IDataProtector ProtectorFor(string interactionId, string secret) => InteractionStoreKeys.ProtectorFor(_protector, interactionId, secret);
}
