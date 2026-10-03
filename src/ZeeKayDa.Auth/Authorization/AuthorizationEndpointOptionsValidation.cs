namespace ZeeKayDa.Auth.Authorization;

internal static class AuthorizationEndpointOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this AuthorizationEndpointOptions authorizationEndpoint) =>
        ValidateOwnValues(authorizationEndpoint).Concat(authorizationEndpoint.Interaction.Validate());

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateOwnValues(AuthorizationEndpointOptions authorizationEndpoint)
    {
        if (authorizationEndpoint.CodeChallengeMethodsSupported is { Count: 0 })
        {
            yield return new(
                "configuration.authorization_endpoint.code_challenge_methods_supported.empty",
                "AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported " +
                "must not be an empty collection. Either set it to null to omit the field from the " +
                "discovery document, or provide at least one value (e.g. CodeChallengeMethod.S256). " +
                "See RFC 7636 §4.3 and RFC 8414 §2.");
        }

        // RFC 9700 §2.1.1 requires authorization codes to be short-lived (max 10 minutes).
        if (authorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.FromSeconds(600))
        {
            yield return new(
                "configuration.authorization_endpoint.authorization_code_lifetime.too_long",
                "AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime must not exceed " +
                "600 seconds (10 minutes). Values above 600 seconds violate the short-lived code requirement " +
                "of RFC 9700 §2.1.1.");
        }

        if (authorizationEndpoint.AuthorizationCodeLifetime <= TimeSpan.Zero)
        {
            yield return new(
                "configuration.authorization_endpoint.authorization_code_lifetime.not_positive",
                "AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime must be greater than zero.");
        }

        if (authorizationEndpoint.MaxRequestContextBytes <= 0)
        {
            yield return new(
                "configuration.authorization_endpoint.max_request_context_bytes.not_positive",
                "AuthorizationServerOptions.AuthorizationEndpoint.MaxRequestContextBytes must be greater than zero.");
        }
    }
}
