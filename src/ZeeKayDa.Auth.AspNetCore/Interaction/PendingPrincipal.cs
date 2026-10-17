using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A principal parked through <see cref="ProviderSignInContext.RedirectToAsync"/>, as
/// <see cref="ProviderSignInInteraction.GetPendingPrincipalAsync"/> reads it back.
/// </summary>
public sealed class PendingPrincipal
{
    internal PendingPrincipal(ExternalIdentity identity, ClaimsPrincipal principal, ProviderDescriptor provider)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(provider);

        Identity = identity;
        Principal = principal;
        Provider = provider;
    }

    /// <summary>Who the user is at the provider: the key a linking page finds the local account by.</summary>
    public ExternalIdentity Identity { get; }

    /// <summary>The principal as the provider returned it, with the framework's reserved claims removed.</summary>
    public ClaimsPrincipal Principal { get; }

    /// <summary>The provider that authenticated it.</summary>
    public ProviderDescriptor Provider { get; }
}
