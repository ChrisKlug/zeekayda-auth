namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// One external provider the host registered through <c>WithProviders</c>, as the login page sees
/// it: an identifier to post back when the user picks it, and a name to put on the button.
/// </summary>
/// <remarks>
/// <see cref="Id"/> is opaque to the host. The page reads it from
/// <see cref="ILoginInteraction.Providers"/> and hands it back to the framework to select that
/// provider; it never writes one, which is what keeps scheme names out of host code.
/// </remarks>
public sealed class ProviderDescriptor
{
    internal ProviderDescriptor(string id, string? displayName)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        Id = id;
        DisplayName = displayName;
    }

    /// <summary>The identifier the login page posts back to select this provider.</summary>
    public string Id { get; }

    /// <summary>
    /// The human-readable name registered for the provider, or <see langword="null"/> when the
    /// registration gave none.
    /// </summary>
    public string? DisplayName { get; }
}
