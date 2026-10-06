using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth;

/// <summary>
/// Validates <see cref="AuthorizationServerOptions"/> top-down against OIDC Discovery 1.0 and
/// RFC 8414: the root's own values, then each group's, then the rules that span groups.
/// </summary>
/// <remarks>
/// Each options group validates itself in a sibling <c>*OptionsValidation.cs</c> file. A rule that
/// reads more than one group lives here, with the parent that owns them all, named by its topic.
/// </remarks>
internal static partial class AuthorizationServerOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this AuthorizationServerOptions options) =>
        // Nothing can be checked against an issuer that does not parse, so that failure stands alone.
        ParseIssuer(options, out var issuerUri) is { } unparsable
            ? [unparsable]
            : ValidateIssuer(options, issuerUri)
                .Concat(ValidateGrantTypes(options))
                .Concat(ValidateCors(options))
                .Concat(ValidateClockSkew(options))
                .Concat(options.Response.Validate())
                .Concat(options.TokenEndpoint.Validate())
                .Concat(options.IdToken.Validate())
                .Concat(options.DiscoveryDocument.Validate())
                .Concat(options.JwksEndpoint.Validate())
                .Concat(options.SigningKeys.Validate())
                .Concat(options.SecurityHeaders.Validate())
                .Concat(options.AuthorizationEndpoint.Validate())
                .Concat(options.EndSessionEndpoint.Validate())
                .Concat(ValidateLifetimeRelationships(options))
                .Concat(ValidateSigningKeyLeadTime(options))
                .Concat(ValidatePkceMatchesTheCodeGrant(options))
                .Concat(ValidateEndpointUris(options, issuerUri));

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateGrantTypes(AuthorizationServerOptions options)
    {
        if (options.GrantTypesSupported is null)
        {
            yield return new(
                "configuration.grant_types_supported.null",
                "AuthorizationServerOptions.GrantTypesSupported must not be null.");
            yield break;
        }

        foreach (var grantType in options.GrantTypesSupported.Where(grantType => !Enum.IsDefined(grantType)))
        {
            yield return new(
                "configuration.grant_types_supported.undefined_value",
                $"AuthorizationServerOptions.GrantTypesSupported contains invalid value '{(int)grantType}'. " +
                $"Expected a valid {nameof(GrantType)} enum member.");
        }
    }

    /// <summary>
    /// Each entry must be a strict absolute origin (<c>scheme://host[:port]</c>) with no path other
    /// than "/", query, fragment, userinfo, wildcards or CRLF.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateCors(AuthorizationServerOptions options)
    {
        if (options.CorsOrigins is null)
        {
            yield return new(
                "configuration.cors_origins.null",
                "AuthorizationServerOptions.CorsOrigins must not be null. Leave it empty to allow no cross-origin caller.");
            yield break;
        }

        var problems = options.CorsOrigins
            .Select((origin, index) => (index, new CorsOrigin(origin, options.Development.AllowHttpLoopbackCorsOrigins).ErrorMessage))
            .Where(entry => entry.ErrorMessage is not null);

        foreach (var (index, problem) in problems)
        {
            yield return new(
                "configuration.cors_origins.invalid",
                $"AuthorizationServerOptions.CorsOrigins[{index}]: {problem}");
        }
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateClockSkew(AuthorizationServerOptions options)
    {
        // A negative tolerance silently rejects tokens before their stated expiry.
        if (options.ClockSkewTolerance < TimeSpan.Zero)
        {
            yield return new(
                "configuration.clock_skew_tolerance.negative",
                "AuthorizationServerOptions.ClockSkewTolerance must be greater than or equal to zero. " +
                "A negative value causes expiry checks to reject tokens before their stated expiry time.");
        }
    }
}
