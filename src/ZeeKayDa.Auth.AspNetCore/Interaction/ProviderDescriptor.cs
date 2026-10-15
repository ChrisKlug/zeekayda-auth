namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// One external provider registered through <c>WithProviders</c>, as the login page sees it.
/// </summary>
/// <remarks>
/// <see cref="Id"/> is opaque: the page hands it back to select the provider, never writes one.
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
    /// The provider's registered display name, or <see langword="null"/>.
    /// </summary>
    public string? DisplayName { get; }
}
