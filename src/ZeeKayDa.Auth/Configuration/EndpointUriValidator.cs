namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates the endpoint URI overrides. RFC 8414 §2 requires all metadata URLs to use HTTPS;
/// RFC 6749 §3.1 and §3.2 carry the same two rules for the authorization and token endpoints
/// alike — a query component is explicitly permitted, a fragment is forbidden. The JWKS,
/// end-session and userinfo routes match on the path alone, so a query on any of them could never
/// be honoured.
/// </summary>
internal static class EndpointUriValidator
{
    /// <summary>
    /// One endpoint override, the code prefix its failures carry, and whether a query component is
    /// prohibited on it.
    /// </summary>
    private readonly record struct EndpointOverride(string PropertyName, string CodePrefix, string? Value, bool RejectQuery);

    internal static void Validate(AuthorizationServerOptions options, Uri issuerUri, List<ZeeKayDaConfigurationFailure> failures)
    {
        EndpointOverride[] endpoints =
        [
            // Full option paths, not nameof(...Uri): that is just "Uri" for every one of them, and
            // the operator could not tell which endpoint the message is about.
            new("AuthorizationEndpoint.Uri", "configuration.authorization_endpoint.uri", options.AuthorizationEndpoint.Uri, RejectQuery: false),
            new("TokenEndpoint.Uri", "configuration.token_endpoint.uri", options.TokenEndpoint.Uri, RejectQuery: false),
            new("JwksEndpoint.Uri", "configuration.jwks_endpoint.uri", options.JwksEndpoint.Uri, RejectQuery: true),
            new("EndSessionEndpoint.Uri", "configuration.end_session_endpoint.uri", options.EndSessionEndpoint.Uri, RejectQuery: true),
            new("UserInfoEndpoint.Uri", "configuration.user_info_endpoint.uri", options.UserInfoEndpoint.Uri, RejectQuery: true),
        ];

        failures.AddRange(endpoints
            .Select(endpoint => ValidateEndpoint(options, issuerUri, endpoint))
            .OfType<ZeeKayDaConfigurationFailure>());
    }

    /// <summary>The endpoint's first broken rule, or <see langword="null"/> when it broke none.</summary>
    private static ZeeKayDaConfigurationFailure? ValidateEndpoint(AuthorizationServerOptions options, Uri issuerUri, EndpointOverride endpoint)
    {
        if (endpoint.Value is null)
            return null;

        if (!Uri.TryCreate(endpoint.Value, UriKind.Absolute, out var uri))
            return new(
                $"{endpoint.CodePrefix}.invalid",
                $"AuthorizationServerOptions.{endpoint.PropertyName} '{endpoint.Value}' is not a valid absolute URI.");

        return ValidateParsedEndpoint(options, issuerUri, endpoint, uri);
    }

    private static ZeeKayDaConfigurationFailure? ValidateParsedEndpoint(
        AuthorizationServerOptions options,
        Uri issuerUri,
        EndpointOverride endpoint,
        Uri uri)
    {
        var (propertyName, codePrefix, value, rejectQuery) = endpoint;

        if (uri.UserInfo.Length > 0)
            return new(
                $"{codePrefix}.userinfo",
                $"AuthorizationServerOptions.{propertyName} '{value}' must not contain user information.");

        if (!ServerUriRules.IsSchemePermitted(uri, options.AllowInsecureIssuer))
            return new(
                $"{codePrefix}.not_https",
                $"AuthorizationServerOptions.{propertyName} '{value}' must use HTTPS. " +
                "Set AllowInsecureIssuer = true to permit HTTP loopback endpoints for local development only.");

        if (ServerUriRules.IsInsecureNonLoopback(uri, options.AllowInsecureIssuer))
            return new(
                $"{codePrefix}.http_non_loopback",
                $"AuthorizationServerOptions.{propertyName} '{value}' uses HTTP for a non-loopback host. " +
                "AllowInsecureIssuer only permits HTTP loopback endpoints for local development and testing.");

        if (!HasSameAuthority(uri, issuerUri))
            return new(
                $"{codePrefix}.authority_mismatch",
                $"AuthorizationServerOptions.{propertyName} '{value}' must use the same authority as " +
                $"AuthorizationServerOptions.Issuer '{options.Issuer}'.");

        if (rejectQuery && uri.Query.Length > 0)
            return new(
                $"{codePrefix}.query",
                $"AuthorizationServerOptions.{propertyName} '{value}' must not contain a query component ('?').");

        // Every endpoint override rejects a fragment.
        if (uri.Fragment.Length > 0)
            return new(
                $"{codePrefix}.fragment",
                $"AuthorizationServerOptions.{propertyName} '{value}' must not contain a fragment component ('#').");

        return null;
    }

    private static bool HasSameAuthority(Uri endpointUri, Uri issuerUri)
        => Uri.Compare(
            endpointUri,
            issuerUri,
            UriComponents.SchemeAndServer,
            UriFormat.SafeUnescaped,
            StringComparison.OrdinalIgnoreCase) == 0;
}
