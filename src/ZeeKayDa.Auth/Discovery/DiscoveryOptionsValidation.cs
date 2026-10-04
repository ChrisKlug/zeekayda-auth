namespace ZeeKayDa.Auth.Discovery;

internal static class DiscoveryOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this DiscoveryOptions discoveryDocument)
    {
        if (discoveryDocument.CacheMaxAge < TimeSpan.Zero)
        {
            yield return new(
                "configuration.discovery_document.cache_max_age.negative",
                "AuthorizationServerOptions.DiscoveryDocument.CacheMaxAge must not be negative.");
        }
    }
}
