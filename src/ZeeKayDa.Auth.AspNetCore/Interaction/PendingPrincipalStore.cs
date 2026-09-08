using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Stores;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>The ticket properties that bind a parked principal to its interaction and record its provider.</summary>
internal static class PendingTicketItems
{
    public const string InteractionId = "zkd:interaction_id";

    public const string Provider = "zkd:provider";
}

/// <summary>
/// A parked external principal, as read back from the interaction store.
/// </summary>
internal sealed record PendingTicket(ClaimsPrincipal Principal, string Provider);

/// <summary>
/// A principal an external provider authenticated, parked while the host's page collects more:
/// a second entry in the interaction store, keyed like the context by the interaction identifier
/// and the secret in its binding cookie, and consumed by the sign-in that completes that
/// interaction.
/// </summary>
/// <remarks>
/// <para>
/// One entry per interaction, so a second tab on the host's collect-more page parks its own
/// principal and reads back its own. The entry shares the interaction's binding: only the
/// browser that started the request can park, read or consume it, and it is unreachable the
/// moment the binding cookie goes.
/// </para>
/// <para>
/// The principal is stored as the provider returned it — every identity, with its authentication
/// type and its name and role claim types — minus the framework's reserved claims, in the ticket
/// format the cookie handler would have used, protected on the host's key ring. The binding and
/// the provider live in the ticket's properties, as they do for the external ticket, so neither
/// is a claim the host could see or a provider could have written.
/// </para>
/// <para>
/// Consuming is a read followed by a remove, not an atomic take. The parked principal is not
/// what makes an interaction complete once: the authorization code store's claim on the
/// interaction is, and a principal read twice by the same browser signs the same person in.
/// </para>
/// </remarks>
internal sealed class PendingPrincipalStore
{
    /// <summary>
    /// How long a host page has to finish with a parked principal. Not sliding, and never past
    /// the interaction's own expiry: a principal parked late in an interaction's life goes with it.
    /// </summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private const string DataProtectionPurpose = "ZeeKayDa.Auth:PendingPrincipal";

    private readonly IInteractionBackingStore _store;
    private readonly InteractionBindingCookie _binding;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly ISanitizingLogger<PendingPrincipalStore> _logger;

    public PendingPrincipalStore(
        IInteractionBackingStore store,
        InteractionBindingCookie binding,
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider,
        ISanitizingLogger<PendingPrincipalStore> logger)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _store = store;
        _binding = binding;
        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// Parks <paramref name="principal"/> for <paramref name="requestContext"/>'s interaction,
    /// replacing any principal already parked for it, under the binding this request carries.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The request carries no binding for the interaction. The resume endpoint reads the context
    /// before anything is parked, so the binding is present; a park without one would be an
    /// entry no browser could ever read.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the write.</exception>
    public async ValueTask ParkAsync(
        HttpContext context,
        ClaimsPrincipal principal,
        AuthorizationRequestContext requestContext,
        string provider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentException.ThrowIfNullOrEmpty(provider);

        var secret = _binding.Read(context, requestContext.Id)
            ?? throw new InvalidOperationException(
                "A principal cannot be parked from a request that carries no binding for its interaction. " +
                "Read the context first; a parked principal is only ever for an interaction this browser holds.");

        var now = _timeProvider.GetUtcNow();
        var expiresAt = Earliest(now + Lifetime, requestContext.ExpiresAt);

        var properties = new AuthenticationProperties { IsPersistent = false, ExpiresUtc = expiresAt };
        properties.Items[PendingTicketItems.InteractionId] = requestContext.Id;
        properties.Items[PendingTicketItems.Provider] = provider;

        var ticket = new AuthenticationTicket(ReservedClaims.Strip(principal), properties, ZeeKayDaCookies.Pending);
        var protectedValue = _protector.Protect(TicketSerializer.Default.Serialize(ticket));

        await Guarded(
            () => _store.SetAsync(InteractionStoreKeys.PendingPrincipal(requestContext.Id, secret), protectedValue, expiresAt, cancellationToken),
            "park the external principal").ConfigureAwait(false);
    }

    /// <summary>
    /// The parked principal bound to <paramref name="interactionId"/>, or <see langword="null"/>
    /// when this browser holds no binding for it, there is none, it has expired, it is protected
    /// under a key this application cannot read, or it names another interaction — never throws
    /// for a value it cannot make sense of.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<PendingTicket?> ReadAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (_binding.Read(context, interactionId) is not { } secret)
            return null;

        return await ReadAsync(interactionId, secret, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the parked principal bound to <paramref name="interactionId"/> and removes the
    /// entry: whichever sign-in completes the interaction takes the principal with it. The
    /// removal is best-effort — a store that refuses it is logged rather than thrown, since the
    /// sign-in or denial in progress should not be replaced by a failure to tidy up, and the
    /// entry is left to its lifetime.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<PendingTicket?> ConsumeAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (_binding.Read(context, interactionId) is not { } secret)
            return null;

        var pending = await ReadAsync(interactionId, secret, cancellationToken).ConfigureAwait(false);
        if (pending is null)
            return null;

        try
        {
            await Guarded(
                () => _store.RemoveAsync(InteractionStoreKeys.PendingPrincipal(interactionId, secret), cancellationToken),
                "remove the parked external principal").ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            _logger.LogError(ex, "Removing a consumed external principal from the store failed; the entry is left to expire.");
        }

        return pending;
    }

    private async ValueTask<PendingTicket?> ReadAsync(string interactionId, string secret, CancellationToken cancellationToken)
    {
        var stored = await Guarded(
            () => _store.GetAsync(InteractionStoreKeys.PendingPrincipal(interactionId, secret), cancellationToken),
            "read the parked external principal").ConfigureAwait(false);

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

        return TicketSerializer.Default.Deserialize(payload) is { } ticket ? Bound(ticket, interactionId) : null;
    }

    /// <summary>
    /// The ticket as a parked principal, or <see langword="null"/> when it is bound to another
    /// interaction, names no provider, or has expired. Data Protection authenticates the bytes,
    /// not which row they sit in, so the identifier inside the ticket is what ties it to the
    /// entry it was read from; and the expiry inside is authoritative, since the store's TTL is
    /// not checked by anything this framework controls.
    /// </summary>
    private PendingTicket? Bound(AuthenticationTicket ticket, string interactionId)
    {
        var items = ticket.Properties.Items;
        var isBound = items.TryGetValue(PendingTicketItems.InteractionId, out var bound)
            && !string.IsNullOrEmpty(bound)
            && InteractionHandoff.IdentifiersMatch(bound, interactionId);

        if (!isBound || !items.TryGetValue(PendingTicketItems.Provider, out var provider) || string.IsNullOrEmpty(provider))
            return null;

        if (ticket.Properties.ExpiresUtc is not { } expiresAt || _timeProvider.GetUtcNow() >= expiresAt)
            return null;

        return new PendingTicket(ReservedClaims.Strip(ticket.Principal), provider);
    }

    private static DateTimeOffset Earliest(DateTimeOffset first, DateTimeOffset second) => first < second ? first : second;
}
