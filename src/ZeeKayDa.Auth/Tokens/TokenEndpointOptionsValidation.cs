namespace ZeeKayDa.Auth.Tokens;

internal static class TokenEndpointOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this TokenEndpointOptions tokenEndpoint) =>
        ValidateLifetimes(tokenEndpoint).Concat(ValidateAdvertisedAuthMethods(tokenEndpoint));

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateLifetimes(TokenEndpointOptions tokenEndpoint)
    {
        if (tokenEndpoint.RefreshTokenLifetime <= TimeSpan.Zero)
        {
            yield return new(
                "configuration.token_endpoint.refresh_token_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime must be greater than zero.");
        }

        // TimeSpan.MaxValue is the explicit, warned "unbounded" sentinel and remains valid here.
        if (tokenEndpoint.AbsoluteFamilyLifetime <= TimeSpan.Zero)
        {
            yield return new(
                "configuration.token_endpoint.absolute_family_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime must be greater than zero.");
        }

        if (tokenEndpoint.AccessTokenLifetime <= TimeSpan.Zero)
        {
            yield return new(
                "configuration.token_endpoint.access_token_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.AccessTokenLifetime must be greater than zero.");
        }

        if (tokenEndpoint.IdTokenLifetime <= TimeSpan.Zero)
        {
            yield return new(
                "configuration.token_endpoint.id_token_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.IdTokenLifetime must be greater than zero.");
        }
    }

    /// <summary>
    /// Null is the default and means "advertise everything the server can do"; an empty filter
    /// would advertise and accept nothing at all, which is never what an operator means.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateAdvertisedAuthMethods(TokenEndpointOptions tokenEndpoint)
    {
        var methods = tokenEndpoint.AdvertisedAuthMethods;

        if (methods is null)
            yield break;

        if (methods.Count == 0)
        {
            yield return new(
                "configuration.token_endpoint.advertised_auth_methods.empty",
                "AuthorizationServerOptions.TokenEndpoint.AdvertisedAuthMethods is an empty set, which " +
                "would accept no client at the token endpoint. Name at least one method, or set it to " +
                "null to advertise every method the registered client authenticators perform.");
            yield break;
        }

        foreach (var problem in methods.Select(AuthMethodProblem).OfType<string>())
            yield return new("configuration.token_endpoint.advertised_auth_methods.invalid_entry", problem);
    }

    private static string? AuthMethodProblem(string? authMethod)
    {
        if (TokenEndpointAuthMethodRules.IsBlank(authMethod))
            return "AuthorizationServerOptions.TokenEndpoint.AdvertisedAuthMethods contains an invalid entry: " +
                "each entry must be a non-empty, non-whitespace string.";

        if (TokenEndpointAuthMethodRules.HasSurroundingWhitespace(authMethod))
            return "AuthorizationServerOptions.TokenEndpoint.AdvertisedAuthMethods contains an invalid entry: " +
                $"'{authMethod}' has leading or trailing whitespace.";

        if (TokenEndpointAuthMethodRules.HasControlCharacters(authMethod))
            return "AuthorizationServerOptions.TokenEndpoint.AdvertisedAuthMethods contains an invalid entry: " +
                $"'{authMethod}' contains one or more control characters.";

        return null;
    }
}
