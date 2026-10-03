namespace ZeeKayDa.Auth.Tokens;

internal static class TokenEndpointOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this TokenEndpointOptions tokenEndpoint) =>
        ValidateLifetimes(tokenEndpoint).Concat(ValidateAuthMethodsSupported(tokenEndpoint));

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

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateAuthMethodsSupported(TokenEndpointOptions tokenEndpoint)
    {
        var methods = tokenEndpoint.AuthMethodsSupported;

        if (methods is not { Count: > 0 })
        {
            yield return new(
                methods is null
                    ? "configuration.token_endpoint.auth_methods_supported.null"
                    : "configuration.token_endpoint.auth_methods_supported.empty",
                "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported must not be null or empty. " +
                "Specify at least one client authentication method (e.g., TokenEndpointAuthMethods.ClientSecretBasic). " +
                "See OAuth 2.0 Security BCP §2.6 (RFC 9700).");
            yield break;
        }

        foreach (var problem in methods.Select(AuthMethodProblem).OfType<string>())
            yield return new("configuration.token_endpoint.auth_methods_supported.invalid_entry", problem);
    }

    private static string? AuthMethodProblem(string? authMethod)
    {
        if (TokenEndpointAuthMethodRules.IsBlank(authMethod))
            return "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported contains an invalid entry: " +
                "each entry must be a non-empty, non-whitespace string.";

        if (TokenEndpointAuthMethodRules.HasSurroundingWhitespace(authMethod))
            return "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported contains an invalid entry: " +
                $"'{authMethod}' has leading or trailing whitespace.";

        if (TokenEndpointAuthMethodRules.HasControlCharacters(authMethod))
            return "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported contains an invalid entry: " +
                $"'{authMethod}' contains one or more control characters.";

        return null;
    }
}
