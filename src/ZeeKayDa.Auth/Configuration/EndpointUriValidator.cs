namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates the endpoint URI overrides. RFC 8414 §2 requires all metadata URLs to use HTTPS;
/// RFC 6749 §3.1 and §3.2 forbid a fragment on the authorization and token endpoints, while
/// a query is explicitly permitted on the authorization endpoint (§3.1) and not prohibited on
/// the token endpoint. The JWKS and end-session routes match on the path alone, so a query on
/// either could never be honoured.
/// </summary>
internal static class EndpointUriValidator
{
    /// <summary>One endpoint override, and whether a query component is prohibited on it.</summary>
    private readonly record struct EndpointOverride(string PropertyName, string? Value, bool RejectQuery);

    internal static void Validate(AuthorizationServerOptions options, Uri issuerUri, List<string> errors)
    {
        EndpointOverride[] endpoints =
        [
            // Full option paths, not nameof(...Uri): that is just "Uri" for every one of them, and
            // the operator could not tell which endpoint the message is about.
            new("AuthorizationEndpoint.Uri", options.AuthorizationEndpoint.Uri, RejectQuery: false),
            new("TokenEndpoint.Uri", options.TokenEndpoint.Uri, RejectQuery: false),
            new("JwksEndpoint.Uri", options.JwksEndpoint.Uri, RejectQuery: true),
            new("EndSessionEndpoint.Uri", options.EndSessionEndpoint.Uri, RejectQuery: true),
        ];

        errors.AddRange(endpoints
            .Select(endpoint => ValidateEndpoint(options, issuerUri, endpoint))
            .OfType<string>());
    }

    /// <summary>The endpoint's first broken rule, or <see langword="null"/> when it broke none.</summary>
    private static string? ValidateEndpoint(AuthorizationServerOptions options, Uri issuerUri, EndpointOverride endpoint)
    {
        if (endpoint.Value is null)
            return null;

        if (!Uri.TryCreate(endpoint.Value, UriKind.Absolute, out var uri))
            return $"AuthorizationServerOptions.{endpoint.PropertyName} '{endpoint.Value}' is not a valid absolute URI.";

        return ValidateParsedEndpoint(options, issuerUri, endpoint, uri);
    }

    private static string? ValidateParsedEndpoint(
        AuthorizationServerOptions options,
        Uri issuerUri,
        EndpointOverride endpoint,
        Uri uri)
    {
        var (propertyName, value, rejectQuery) = endpoint;

        if (uri.UserInfo.Length > 0)
            return $"AuthorizationServerOptions.{propertyName} '{value}' must not contain user information.";

        if (!ServerUriRules.IsSchemePermitted(uri, options.AllowInsecureIssuer))
            return $"AuthorizationServerOptions.{propertyName} '{value}' must use HTTPS. " +
                "Set AllowInsecureIssuer = true to permit HTTP loopback endpoints for local development only.";

        if (ServerUriRules.IsInsecureNonLoopback(uri, options.AllowInsecureIssuer))
            return $"AuthorizationServerOptions.{propertyName} '{value}' uses HTTP for a non-loopback host. " +
                "AllowInsecureIssuer only permits HTTP loopback endpoints for local development and testing.";

        if (!HasSameAuthority(uri, issuerUri))
            return $"AuthorizationServerOptions.{propertyName} '{value}' must use the same authority as " +
                $"AuthorizationServerOptions.Issuer '{options.Issuer}'.";

        if (rejectQuery && uri.Query.Length > 0)
            return $"AuthorizationServerOptions.{propertyName} '{value}' must not contain a query component ('?').";

        // Every endpoint override rejects a fragment.
        if (uri.Fragment.Length > 0)
            return $"AuthorizationServerOptions.{propertyName} '{value}' must not contain a fragment component ('#').";

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
