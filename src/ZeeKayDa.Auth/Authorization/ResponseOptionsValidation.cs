namespace ZeeKayDa.Auth.Authorization;

internal static class ResponseOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this ResponseOptions response)
    {
        if (response.TypesSupported is null)
        {
            yield return new(
                "configuration.response.types_supported.null",
                "AuthorizationServerOptions.Response.TypesSupported must not be null.");
        }
        else if (response.TypesSupported.Count == 0)
        {
            yield return new(
                "configuration.response.types_supported.empty",
                "AuthorizationServerOptions.Response.TypesSupported must contain at least one value.");
        }

        if (response.ModesSupported is null)
        {
            yield return new(
                "configuration.response.modes_supported.null",
                "AuthorizationServerOptions.Response.ModesSupported must not be null.");
        }
    }
}
