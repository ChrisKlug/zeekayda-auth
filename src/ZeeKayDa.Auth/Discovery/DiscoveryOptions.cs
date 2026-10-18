using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Discovery document configuration options.
/// </summary>
public sealed class DiscoveryOptions
{
    private TimeSpan _cacheMaxAge = TimeSpan.FromHours(1);
    private bool _frozen;

    /// <summary>
    /// Gets or sets the discovery response's <c>Cache-Control</c> <c>max-age</c>, in whole seconds;
    /// below one second emits <c>no-store</c>. Defaults to one hour.
    /// </summary>
    public TimeSpan CacheMaxAge
    {
        get => _cacheMaxAge;
        set => _cacheMaxAge = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.DiscoveryDocument.CacheMaxAge");
    }

    /// <summary>Refuses any later change to these options.</summary>
    internal void Freeze() => _frozen = true;
}
