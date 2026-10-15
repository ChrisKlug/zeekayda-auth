using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A principal parked through <see cref="ProviderSignInContext.RedirectToAsync"/>, as
/// <see cref="ProviderSignInInteraction.GetPendingPrincipalAsync"/> reads it back.
/// </summary>
public sealed class PendingPrincipal
{
    internal PendingPrincipal(ClaimsPrincipal principal, ProviderDescriptor provider)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(provider);

        Principal = principal;
        Provider = provider;
    }

    /// <summary>The principal as the provider returned it, with the framework's reserved claims removed.</summary>
    public ClaimsPrincipal Principal { get; }

    /// <summary>The provider that authenticated it.</summary>
    public ProviderDescriptor Provider { get; }
}
