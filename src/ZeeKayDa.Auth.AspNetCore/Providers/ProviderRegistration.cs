using Microsoft.AspNetCore.Authentication;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>One scheme <c>WithProviders</c> observed, kept in the framework's own scheme map.</summary>
/// <param name="Name">The scheme name, which is also the provider identifier the login page sees.</param>
/// <param name="DisplayName">The scheme's display name, as registered.</param>
/// <param name="HandlerType">The handler the framework activates for this provider.</param>
internal sealed record ProviderRegistration(string Name, string? DisplayName, Type HandlerType)
{
    /// <summary>What the login page sees of this provider.</summary>
    public ProviderDescriptor Descriptor { get; } = new(Name, DisplayName);

    /// <summary>The scheme the framework initialises the handler for.</summary>
    public AuthenticationScheme Scheme { get; } = new(Name, DisplayName, HandlerType);
}
