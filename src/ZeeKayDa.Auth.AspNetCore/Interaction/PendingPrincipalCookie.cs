using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>The claims that bind a parked principal to its interaction and record its provider.</summary>
internal static class PendingPrincipalClaimTypes
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
internal sealed class PendingPrincipalCookie
{
    /// <summary>
    /// Parks <paramref name="principal"/>, bound to <paramref name="interactionId"/>. The
    /// framework's reserved claims are stripped first, so the binding is the framework's alone.
    /// </summary>
    public Task WriteAsync(HttpContext context, ClaimsPrincipal principal, string interactionId, string provider)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);
        ArgumentException.ThrowIfNullOrEmpty(provider);

        var claims = principal.Claims.Where(claim => !ReservedClaims.IsReserved(claim)).ToList();
        claims.Add(new Claim(PendingPrincipalClaimTypes.InteractionId, interactionId));
        claims.Add(new Claim(PendingPrincipalClaimTypes.Provider, provider));

        return context.SignInAsync(
            ZeeKayDaCookies.Pending,
            new ClaimsPrincipal(new ClaimsIdentity(claims, provider)),
            new AuthenticationProperties { IsPersistent = false });
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
        return result.Succeeded && result.Principal is { } principal ? Bound(principal, interactionId) : null;
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
        if (!result.Succeeded || result.Principal is null)
            return null;

        await context.SignOutAsync(ZeeKayDaCookies.Pending).ConfigureAwait(false);
        return Bound(result.Principal, interactionId);
    }

    private static PendingTicket? Bound(ClaimsPrincipal principal, string interactionId)
    {
        var bound = principal.FindFirstValue(PendingPrincipalClaimTypes.InteractionId);
        var provider = principal.FindFirstValue(PendingPrincipalClaimTypes.Provider);

        if (string.IsNullOrEmpty(bound) || string.IsNullOrEmpty(provider)
            || !InteractionHandoff.IdentifiersMatch(bound, interactionId))
        {
            return null;
        }

        return new PendingTicket(ReservedClaims.Strip(principal), provider);
    }
}
