using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates <c>TokenEndpoint.AuthMethodsSupported</c>, on its own and against the advertised
/// grant types, recording an error for every rule it breaks.
/// </summary>
internal static class AuthMethodsSupportedValidator
{
    private const string TokenEndpointAuthMethodsRequiredMessage =
        "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported must not be null or empty. " +
        "Specify at least one client authentication method (e.g., TokenEndpointAuthMethods.ClientSecretBasic). " +
        "See OAuth 2.0 Security BCP §2.6 (RFC 9700).";

    /// <summary>
    /// Startup validation error for the cross-group constraint that forbids
    /// advertising the <c>client_credentials</c> grant with only <c>none</c> token endpoint auth.
    /// </summary>
    /// <remarks>
    /// RFC 6749 §4.4 requires client authentication for the client credentials grant and RFC 9700
    /// §2.6 requires strong token endpoint client authentication.
    /// </remarks>
    private const string ClientCredentialsRequiresNonNoneTokenAuthMethodMessage =
        "GrantTypesSupported includes 'client_credentials', which requires confidential clients. " +
        "TokenEndpoint.AuthMethodsSupported must contain at least one method other than 'none'. " +
        "See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).";

    internal static void Validate(AuthorizationServerOptions options, List<string> errors)
    {
        var methods = options.TokenEndpoint.AuthMethodsSupported;

        if (methods is not { Count: > 0 })
        {
            errors.Add(TokenEndpointAuthMethodsRequiredMessage);
            return;
        }

        errors.AddRange(methods.Select(ValidateEntry).OfType<string>());

        if (AdvertisesClientCredentialsWithOnlyNone(options))
            errors.Add(ClientCredentialsRequiresNonNoneTokenAuthMethodMessage);
    }

    /// <summary>The entry's first broken rule, or <see langword="null"/> when it broke none.</summary>
    private static string? ValidateEntry(string? authMethod)
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

    /// <summary>
    /// The <c>client_credentials</c> grant is advertised, but no method other than <c>none</c> is:
    /// the grant requires client authentication, so no client could ever use it.
    /// </summary>
    private static bool AdvertisesClientCredentialsWithOnlyNone(AuthorizationServerOptions options) =>
        options.GrantTypesSupported is { } grants
        && grants.Contains(GrantType.ClientCredentials)
        && TokenEndpointAuthMethodRules.AllowsOnlyNone(options.TokenEndpoint.AuthMethodsSupported);
}
