namespace ZeeKayDa.Auth.Discovery;

internal static class JwksEndpointOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this JwksEndpointOptions jwksEndpoint)
    {
        if (jwksEndpoint.CacheMaxAge < TimeSpan.Zero)
        {
            yield return new(
                "configuration.jwks_endpoint.cache_max_age.negative",
                "AuthorizationServerOptions.JwksEndpoint.CacheMaxAge must not be negative.");
        }
    }
}
