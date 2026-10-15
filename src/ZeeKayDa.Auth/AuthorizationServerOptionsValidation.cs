using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth;

/// <summary>
/// Validates <see cref="AuthorizationServerOptions"/>: the root's values, each group's in its own
/// <c>*OptionsValidation.cs</c>, then the cross-group rules.
/// </summary>
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
        if (options.ClockSkewTolerance < TimeSpan.Zero)
        {
            yield return new(
                "configuration.clock_skew_tolerance.negative",
                "AuthorizationServerOptions.ClockSkewTolerance must be greater than or equal to zero. " +
                "A negative value causes expiry checks to reject tokens before their stated expiry time.");
        }
    }
}
