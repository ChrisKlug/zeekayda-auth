using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>The ticket properties that bind a parked principal to its interaction and record its provider.</summary>
internal static class PendingTicketItems
{
    public const string InteractionId = "zkd:interaction_id";

    public const string Provider = "zkd:provider";
}

/// <summary>
/// A parked external principal, as read back from <c>zkd.pending</c>.
/// </summary>
internal sealed record PendingTicket(ClaimsPrincipal Principal, string Provider);

/// <summary>
/// The <c>zkd.pending</c> cookie: a principal an external provider authenticated, parked while
/// the host's page collects more, bound to the interaction it belongs to and consumed by the
/// sign-in that completes that interaction.
/// </summary>
/// <remarks>
/// The principal is stored as the provider returned it — every identity, with its authentication
/// type and its name and role claim types — minus the framework's reserved claims. The binding
/// lives in the ticket's properties, as it does for the external ticket, so it is never a claim
/// the host could see or a provider could have written.
/// </remarks>
internal sealed class PendingPrincipalCookie
{
    /// <summary>Parks <paramref name="principal"/>, bound to <paramref name="interactionId"/>.</summary>
    public Task WriteAsync(HttpContext context, ClaimsPrincipal principal, string interactionId, string provider)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);
        ArgumentException.ThrowIfNullOrEmpty(provider);

        var properties = new AuthenticationProperties { IsPersistent = false };
        properties.Items[PendingTicketItems.InteractionId] = interactionId;
        properties.Items[PendingTicketItems.Provider] = provider;

        return context.SignInAsync(ZeeKayDaCookies.Pending, ReservedClaims.Strip(principal), properties);
    }

    /// <summary>
    /// The parked principal bound to <paramref name="interactionId"/>, or <see langword="null"/>
    /// when there is none, it has expired, or it is bound to another interaction.
    /// </summary>
    public async Task<PendingTicket?> ReadAsync(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var result = await context.AuthenticateAsync(ZeeKayDaCookies.Pending).ConfigureAwait(false);
        return result.Succeeded && result.Ticket is { } ticket ? Bound(ticket, interactionId) : null;
    }

    /// <summary>
    /// Reads the parked principal bound to <paramref name="interactionId"/> and removes the
    /// cookie whether or not it was bound to it: a parked principal is single-use, and one left
    /// behind by another interaction has nothing to complete.
    /// </summary>
    public async Task<PendingTicket?> ConsumeAsync(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var result = await context.AuthenticateAsync(ZeeKayDaCookies.Pending).ConfigureAwait(false);
        if (!result.Succeeded || result.Ticket is not { } ticket)
            return null;

        await context.SignOutAsync(ZeeKayDaCookies.Pending).ConfigureAwait(false);
        return Bound(ticket, interactionId);
    }

    private static PendingTicket? Bound(AuthenticationTicket ticket, string interactionId)
    {
        var items = ticket.Properties.Items;
        var isBound = items.TryGetValue(PendingTicketItems.InteractionId, out var bound)
            && !string.IsNullOrEmpty(bound)
            && InteractionHandoff.IdentifiersMatch(bound, interactionId);

        if (!isBound || !items.TryGetValue(PendingTicketItems.Provider, out var provider) || string.IsNullOrEmpty(provider))
            return null;

        return new PendingTicket(ReservedClaims.Strip(ticket.Principal), provider);
    }
}
