using System.Diagnostics.CodeAnalysis;
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

    public const string LoginIdentifier = "zkd:login_id";

    public const string AddAccount = "zkd:add_account";
}

/// <summary>A parked external principal, as read back from the interaction store, with the host's placement for it.</summary>
internal sealed record PendingTicket(ClaimsPrincipal Principal, string Provider, AccountPlacement Placement);

/// <summary>
/// A principal an external provider authenticated, parked while the host's page collects more,
/// keyed and sealed like the interaction context under the interaction's binding.
/// </summary>
/// <remarks>
/// The interaction and provider ride in ticket properties, which no provider could have written.
/// Consuming is not an atomic take: the code store's completion claim is what makes an interaction
/// complete once.
/// </remarks>
internal sealed class PendingPrincipalStore(
    IInteractionBackingStore store,
    InteractionBindingCookie binding,
    IDataProtectionProvider dataProtectionProvider,
    TimeProvider timeProvider,
    SanitizingLogger<PendingPrincipalStore> logger)
{
    /// <summary>How long a host page has to finish with a parked principal; never past the interaction's expiry.</summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private const string DataProtectionPurpose = "ZeeKayDa.Auth:PendingPrincipal";

    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);

    /// <summary>Parks <paramref name="ticket"/> for the interaction, replacing any already parked.</summary>
    /// <exception cref="InvalidOperationException">
    /// The request carries no binding for the interaction. The resume endpoint reads the context
    /// before anything is parked, so the binding is present; a park without one would be an
    /// entry no browser could ever read.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the write.</exception>
    public async ValueTask ParkAsync(
        HttpContext context,
        PendingTicket ticket,
        AuthorizationRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentException.ThrowIfNullOrEmpty(ticket.Provider);

        var secret = binding.Read(context, requestContext.Id)
            ?? throw new InvalidOperationException(
                "A principal cannot be parked from a request that carries no binding for its interaction. " +
                "Read the context first; a parked principal is only ever for an interaction this browser holds.");

        var now = timeProvider.GetUtcNow();
        var expiresAt = Earliest(now + Lifetime, requestContext.ExpiresAt);

        var properties = new AuthenticationProperties { IsPersistent = false, ExpiresUtc = expiresAt };
        properties.Items[PendingTicketItems.InteractionId] = requestContext.Id;
        properties.Items[PendingTicketItems.Provider] = ticket.Provider;
        properties.Items[PendingTicketItems.LoginIdentifier] = ticket.Placement.LoginIdentifier;
        properties.Items[PendingTicketItems.AddAccount] = ticket.Placement.AddAccount ? "true" : null;

        var stored = new AuthenticationTicket(ReservedClaims.Strip(ticket.Principal), properties, ZeeKayDaCookies.Pending);
        var protectedValue = ProtectorFor(requestContext.Id, secret).Protect(TicketSerializer.Default.Serialize(stored));

        await Guarded(
            () => store.SetAsync(InteractionStoreKeys.PendingPrincipal(requestContext.Id, secret), protectedValue, expiresAt, cancellationToken),
            "park the external principal").ConfigureAwait(false);
    }

    /// <summary>The parked principal bound to <paramref name="interactionId"/>; anything unreadable is <see langword="null"/>.</summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<PendingTicket?> ReadAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        // A caller that stopped waiting gets the cancellation, not an absence it might act on.
        cancellationToken.ThrowIfCancellationRequested();

        if (binding.Read(context, interactionId) is not { } secret)
            return null;

        return await ReadAsync(interactionId, secret, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads and removes the parked principal; the removal is best-effort, so a failure to tidy up
    /// never replaces the sign-in or denial in progress.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The backing store could not complete the read.</exception>
    public async ValueTask<PendingTicket?> ConsumeAsync(HttpContext context, string interactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        cancellationToken.ThrowIfCancellationRequested();

        if (binding.Read(context, interactionId) is not { } secret)
            return null;

        var pending = await ReadAsync(interactionId, secret, cancellationToken).ConfigureAwait(false);
        if (pending is null)
            return null;

        try
        {
            await Guarded(
                () => store.RemoveAsync(InteractionStoreKeys.PendingPrincipal(interactionId, secret), cancellationToken),
                "remove the parked external principal").ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            logger.LogError(ex, "Removing a consumed external principal from the store failed; the entry is left to expire.");
        }

        return pending;
    }

    private async ValueTask<PendingTicket?> ReadAsync(string interactionId, string secret, CancellationToken cancellationToken)
    {
        var stored = await Guarded(
            () => store.GetAsync(InteractionStoreKeys.PendingPrincipal(interactionId, secret), cancellationToken),
            "read the parked external principal").ConfigureAwait(false);

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

        return TryDeserialize(payload, out var ticket) ? Bound(ticket, interactionId) : null;
    }

    /// <summary>The ticket in <paramref name="payload"/>; bytes that are not one read as absent, never as an exception.</summary>
    private static bool TryDeserialize(byte[] payload, [NotNullWhen(true)] out AuthenticationTicket? ticket)
    {
        try
        {
            ticket = TicketSerializer.Default.Deserialize(payload);
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException or ArgumentException or FormatException)
        {
            ticket = null;
        }

        return ticket is not null;
    }

    private IDataProtector ProtectorFor(string interactionId, string secret) => InteractionStoreKeys.ProtectorFor(_protector, interactionId, secret);

    /// <summary>
    /// The ticket as a parked principal, if it names this interaction, a provider and an unexpired
    /// lifetime: neither the sealing purpose nor the store's TTL is trusted alone.
    /// </summary>
    private PendingTicket? Bound(AuthenticationTicket ticket, string interactionId)
    {
        if (!IsBoundTo(ticket, interactionId) || IsExpired(ticket))
            return null;

        var provider = ProviderOf(ticket);
        return provider is null ? null : new PendingTicket(ReservedClaims.Strip(ticket.Principal), provider, PlacementOf(ticket));
    }

    private static AccountPlacement PlacementOf(AuthenticationTicket ticket) => new(
        ticket.Properties.Items.TryGetValue(PendingTicketItems.LoginIdentifier, out var loginIdentifier) && !string.IsNullOrEmpty(loginIdentifier)
            ? loginIdentifier
            : null,
        ticket.Properties.Items.TryGetValue(PendingTicketItems.AddAccount, out var addAccount) && addAccount == "true");

    private static bool IsBoundTo(AuthenticationTicket ticket, string interactionId) =>
        ticket.Properties.Items.TryGetValue(PendingTicketItems.InteractionId, out var bound)
        && !string.IsNullOrEmpty(bound)
        && InteractionHandoff.IdentifiersMatch(bound, interactionId);

    private bool IsExpired(AuthenticationTicket ticket) =>
        ticket.Properties.ExpiresUtc is not { } expiresAt || timeProvider.GetUtcNow() >= expiresAt;

    private static string? ProviderOf(AuthenticationTicket ticket) =>
        ticket.Properties.Items.TryGetValue(PendingTicketItems.Provider, out var provider) && !string.IsNullOrEmpty(provider)
            ? provider
            : null;

    private static DateTimeOffset Earliest(DateTimeOffset first, DateTimeOffset second) => first < second ? first : second;
}
