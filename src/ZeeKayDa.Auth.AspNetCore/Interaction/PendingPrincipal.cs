using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A principal an external provider authenticated that the host parked, through
/// <see cref="ProviderSignInContext.RedirectToAsync"/>, rather than promoted: what the page it
/// redirected to reads back with <see cref="ILoginInteraction.GetPendingPrincipalAsync"/>.
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
