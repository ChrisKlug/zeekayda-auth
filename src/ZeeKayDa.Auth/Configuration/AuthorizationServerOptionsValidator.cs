using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Security;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates <see cref="AuthorizationServerOptions"/> at startup according to the rules mandated
/// by the OIDC Discovery 1.0 and RFC 8414 specifications.
/// </summary>
/// <remarks>
/// This validator is registered via <c>AddZeeKayDaAuth()</c>, which registers the options with
/// <c>AddZeeKayDaOptions</c>, so that misconfigured servers fail loudly at startup rather than
/// silently at the first request. It is a pure read-only check of the host's values as configured,
/// and async checks (e.g. scope presence) are handled by hosted services. The issuer,
/// the endpoint URI overrides and the token endpoint's auth methods each have their own
/// validator; this class calls them in order and keeps the single-group checks.
/// </remarks>
internal sealed class AuthorizationServerOptionsValidator : ZeeKayDaOptionsValidator<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    protected override void Validate(
        string? name,
        AuthorizationServerOptions options,
        ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        // Nothing below can be checked against an issuer that does not parse, so those two
        // failures end validation on their own.
        if (!IssuerValidator.TryParse(options, failures, out var issuerUri))
            return;

        IssuerValidator.Validate(options, issuerUri, failures);
        ValidateResponse(options, failures);
        ValidateGrantTypes(options, failures);
        AuthMethodsSupportedValidator.Validate(options, failures);
        ValidateTokenEndpointLifetimes(options, failures);
        ValidateIdToken(options, failures);
        ValidateCaching(options, failures);
        ValidateCors(options, failures);
        ValidateSecurityHeaders(options, failures);
        ValidateAuthorizationEndpoint(options, failures);
        ValidateClockSkew(options, failures);
        EndpointUriValidator.Validate(options, issuerUri, failures);
    }

    /// <summary>Validates the <c>Response</c> options group.</summary>
    private static void ValidateResponse(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (options.Response.TypesSupported is null)
        {
            failures.Add(new(
                "configuration.response.types_supported.null",
                "AuthorizationServerOptions.Response.TypesSupported must not be null."));
        }
        else if (options.Response.TypesSupported.Count == 0)
        {
            failures.Add(new(
                "configuration.response.types_supported.empty",
                "AuthorizationServerOptions.Response.TypesSupported must contain at least one value."));
        }

        if (options.Response.ModesSupported is null)
        {
            failures.Add(new(
                "configuration.response.modes_supported.null",
                "AuthorizationServerOptions.Response.ModesSupported must not be null."));
        }
    }

    /// <summary>Validates the root-level <c>GrantTypesSupported</c>.</summary>
    private static void ValidateGrantTypes(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (options.GrantTypesSupported is null)
        {
            failures.Add(new(
                "configuration.grant_types_supported.null",
                "AuthorizationServerOptions.GrantTypesSupported must not be null."));
        }
        else
        {
            var invalidGrantTypes = options.GrantTypesSupported.Where(grantType => !Enum.IsDefined(grantType));

            foreach (var grantType in invalidGrantTypes)
            {
                failures.Add(new(
                    "configuration.grant_types_supported.undefined_value",
                    $"AuthorizationServerOptions.GrantTypesSupported contains invalid value '{(int)grantType}'. " +
                    $"Expected a valid {nameof(GrantType)} enum member."));
            }
        }
    }

    /// <summary>
    /// Validates the <c>IdToken</c> options group. Null is the default and means "advertise the
    /// whole published key set"; an empty filter would advertise nothing at all, which is never
    /// what an operator means. A filter that excludes the signing key's own algorithm is caught
    /// at startup by <c>SigningKeyRingStartupVerifier</c>, the first point at which the key set exists.
    /// </summary>
    private static void ValidateIdToken(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (options.IdToken.AdvertisedSigningAlgorithms is { Count: 0 })
        {
            failures.Add(new(
                "configuration.id_token.advertised_signing_algorithms.empty",
                "AuthorizationServerOptions.IdToken.AdvertisedSigningAlgorithms is an empty set, which " +
                "would advertise no ID token signing algorithm at all. Name at least one algorithm, or " +
                "set it to null to advertise every algorithm in the published signing key set."));
        }
    }

    /// <summary>Validates the cache lifetimes of the <c>DiscoveryDocument</c> and <c>JwksEndpoint</c> groups.</summary>
    private static void ValidateCaching(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (options.DiscoveryDocument.CacheMaxAge < TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.discovery_document.cache_max_age.negative",
                "AuthorizationServerOptions.DiscoveryDocument.CacheMaxAge must not be negative."));
        }

        if (options.JwksEndpoint.CacheMaxAge < TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.jwks_endpoint.cache_max_age.negative",
                "AuthorizationServerOptions.JwksEndpoint.CacheMaxAge must not be negative."));
        }
    }

    /// <summary>
    /// Validates the CORS allowlist: each entry must be a strict absolute origin
    /// (<c>scheme://host[:port]</c>) with no path other than "/", query, fragment, userinfo,
    /// wildcards or CRLF. Invalid entries fail startup.
    /// </summary>
    private static void ValidateCors(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        var problems = options.CorsOrigins
            .Select(origin => new CorsOrigin(origin, options.AllowInsecureIssuer).ErrorMessage)
            .OfType<string>();

        foreach (var problem in problems)
        {
            failures.Add(new(
                "configuration.cors_origins.invalid",
                $"AuthorizationServerOptions.CorsOrigins: {problem}"));
        }
    }

    /// <summary>
    /// Validates the <c>SecurityHeaders</c> enum values at startup so an out-of-range cast produces
    /// a startup failure consistent with all other misconfiguration, rather than a 500 at request time.
    /// </summary>
    private static void ValidateSecurityHeaders(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (!Enum.IsDefined(options.SecurityHeaders.ReferrerPolicy))
        {
            failures.Add(new(
                "configuration.security_headers.referrer_policy.undefined_value",
                $"AuthorizationServerOptions.SecurityHeaders.ReferrerPolicy value " +
                $"'{(int)options.SecurityHeaders.ReferrerPolicy}' is not a valid {nameof(ReferrerPolicy)} enum member."));
        }

        if (!Enum.IsDefined(options.SecurityHeaders.CrossOriginResourcePolicy))
        {
            failures.Add(new(
                "configuration.security_headers.cross_origin_resource_policy.undefined_value",
                $"AuthorizationServerOptions.SecurityHeaders.CrossOriginResourcePolicy value " +
                $"'{(int)options.SecurityHeaders.CrossOriginResourcePolicy}' is not a valid {nameof(CrossOriginResourcePolicy)} enum member."));
        }
    }

    /// <summary>Validates the root-level <c>ClockSkewTolerance</c>, on its own and against the code lifetime.</summary>
    private static void ValidateClockSkew(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        // A negative ClockSkewTolerance silently rejects tokens before their stated
        // expiry, producing false rejections with no surfaced error.
        if (options.ClockSkewTolerance < TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.clock_skew_tolerance.negative",
                "AuthorizationServerOptions.ClockSkewTolerance must be greater than or equal to zero. " +
                "A negative value causes expiry checks to reject tokens before their stated expiry time."));
        }

        // A tolerance >= half the authorization code lifetime effectively extends the acceptance
        // window past the code's intended expiry, undermining the short-lived code guarantee of
        // RFC 9700 §2.1.1.
        if (ClockSkewReachesHalfTheCodeLifetime(options))
        {
            var halfCodeLifetime = options.AuthorizationEndpoint.AuthorizationCodeLifetime / 2;
            failures.Add(new(
                "configuration.clock_skew_tolerance.too_large",
                $"AuthorizationServerOptions.ClockSkewTolerance ({options.ClockSkewTolerance}) is greater than or " +
                $"equal to half of AuthorizationCodeLifetime ({halfCodeLifetime}). A tolerance this large effectively " +
                "extends the authorization code acceptance window past its intended expiry."));
        }
    }

    /// <summary>
    /// A non-negative tolerance of at least half a positive code lifetime. A negative tolerance or
    /// a non-positive lifetime is reported by its own rule, so it is not also reported here.
    /// </summary>
    private static bool ClockSkewReachesHalfTheCodeLifetime(AuthorizationServerOptions options) =>
        options.ClockSkewTolerance >= TimeSpan.Zero
        && options.AuthorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.Zero
        && options.ClockSkewTolerance >= options.AuthorizationEndpoint.AuthorizationCodeLifetime / 2;

    /// <summary>Validates the token lifetimes of the <c>TokenEndpoint</c> options group.</summary>
    private static void ValidateTokenEndpointLifetimes(
        AuthorizationServerOptions options,
        ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        // A zero or negative refresh token lifetime is nonsensical and must be rejected at startup.
        if (options.TokenEndpoint.RefreshTokenLifetime <= TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.token_endpoint.refresh_token_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime must be greater than zero."));
        }

        // RefreshTokenLifetime must be >= AuthorizationCodeLifetime so the authorization code
        // tombstone retention window covers the full code validity window — otherwise a delayed
        // code replay could escape the RFC 9700 §2.1.1 family-revocation mandate.
        if (RefreshTokensExpireBeforeCodes(options))
        {
            failures.Add(new(
                "configuration.token_endpoint.refresh_token_lifetime.shorter_than_code_lifetime",
                "AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime must be greater than or equal to " +
                "AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime to ensure tombstone " +
                "retention covers the authorization code validity window."));
        }

        // A zero or negative absolute family lifetime is nonsensical and must be rejected at
        // startup. TimeSpan.MaxValue is the explicit, warned "unbounded" sentinel and remains
        // valid here.
        if (options.TokenEndpoint.AbsoluteFamilyLifetime <= TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.token_endpoint.absolute_family_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime must be greater than zero."));
        }

        if (options.TokenEndpoint.AccessTokenLifetime <= TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.token_endpoint.access_token_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.AccessTokenLifetime must be greater than zero."));
        }

        if (options.TokenEndpoint.IdTokenLifetime <= TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.token_endpoint.id_token_lifetime.not_positive",
                "AuthorizationServerOptions.TokenEndpoint.IdTokenLifetime must be greater than zero."));
        }
    }

    /// <summary>
    /// Both lifetimes positive, and the refresh token's shorter than the code's. A non-positive
    /// lifetime is reported by its own rule, so it is not also reported here.
    /// </summary>
    private static bool RefreshTokensExpireBeforeCodes(AuthorizationServerOptions options) =>
        options.TokenEndpoint.RefreshTokenLifetime > TimeSpan.Zero
        && options.AuthorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.Zero
        && options.TokenEndpoint.RefreshTokenLifetime < options.AuthorizationEndpoint.AuthorizationCodeLifetime;

    /// <summary>Validates the <c>AuthorizationEndpoint</c> options group.</summary>
    private static void ValidateAuthorizationEndpoint(
        AuthorizationServerOptions options,
        ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (options.AuthorizationEndpoint.CodeChallengeMethodsSupported is { Count: 0 })
        {
            failures.Add(new(
                "configuration.authorization_endpoint.code_challenge_methods_supported.empty",
                "AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported " +
                "must not be an empty collection. Either set it to null to omit the field from the " +
                "discovery document, or provide at least one value (e.g. CodeChallengeMethod.S256). " +
                "See RFC 7636 §4.3 and RFC 8414 §2."));
        }

        // PKCE with S256 is what makes the authorization code grant safe to serve (RFC 9700
        // §2.1.1), and the token endpoint enforces exactly that method. A host serving the grant
        // without advertising S256 would be telling clients the control is absent while relying
        // on it — so the two settings must agree before any traffic is accepted.
        if (ServesCodeGrantWithoutS256(options))
        {
            failures.Add(new(
                "configuration.authorization_endpoint.code_challenge_methods_supported.s256_missing",
                "AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported must " +
                "contain CodeChallengeMethod.S256 when GrantTypesSupported contains GrantType.AuthorizationCode. " +
                "PKCE with S256 is mandatory for the authorization code grant (OAuth 2.1 §4.1.1, RFC 9700 §2.1.1) " +
                "and the token endpoint enforces it for every client."));
        }

        // RFC 9700 §2.1.1 requires authorization codes to be short-lived (max 10 minutes).
        if (options.AuthorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.FromSeconds(600))
        {
            failures.Add(new(
                "configuration.authorization_endpoint.authorization_code_lifetime.too_long",
                "AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime must not exceed " +
                "600 seconds (10 minutes). Values above 600 seconds violate the short-lived code requirement " +
                "of RFC 9700 §2.1.1."));
        }

        // A zero or negative lifetime is nonsensical and must be rejected at startup.
        if (options.AuthorizationEndpoint.AuthorizationCodeLifetime <= TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.authorization_endpoint.authorization_code_lifetime.not_positive",
                "AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime must be greater than zero."));
        }

        if (options.AuthorizationEndpoint.MaxRequestContextBytes <= 0)
        {
            failures.Add(new(
                "configuration.authorization_endpoint.max_request_context_bytes.not_positive",
                "AuthorizationServerOptions.AuthorizationEndpoint.MaxRequestContextBytes must be greater than zero."));
        }

        ValidateInteractionPath(
            options.AuthorizationEndpoint.Interaction.ErrorPath,
            "AuthorizationEndpoint.Interaction.ErrorPath",
            "configuration.authorization_endpoint.interaction.error_path.unsafe",
            failures);
        ValidateInteractionPath(
            options.AuthorizationEndpoint.Interaction.LoginPath,
            "AuthorizationEndpoint.Interaction.LoginPath",
            "configuration.authorization_endpoint.interaction.login_path.unsafe",
            failures);
        ValidateInteractionPath(
            options.AuthorizationEndpoint.Interaction.ConsentPath,
            "AuthorizationEndpoint.Interaction.ConsentPath",
            "configuration.authorization_endpoint.interaction.consent_path.unsafe",
            failures);
        ValidateInteractionPath(
            options.EndSessionEndpoint.LogoutPath,
            "EndSessionEndpoint.LogoutPath",
            "configuration.end_session_endpoint.logout_path.unsafe",
            failures);
        ValidateInteractionPath(
            options.EndSessionEndpoint.SignedOutPath,
            "EndSessionEndpoint.SignedOutPath",
            "configuration.end_session_endpoint.signed_out_path.unsafe",
            failures);
    }

    /// <summary>The authorization code grant is advertised, but PKCE's S256 method is not.</summary>
    private static bool ServesCodeGrantWithoutS256(AuthorizationServerOptions options) =>
        options.GrantTypesSupported is { } grants &&
        grants.Contains(GrantType.AuthorizationCode) &&
        options.AuthorizationEndpoint.CodeChallengeMethodsSupported?.Contains(CodeChallengeMethod.S256) != true;

    /// <summary>
    /// Rejects an interaction path a browser could resolve to another origin. Every one of these
    /// is a redirect destination the framework builds itself, so a malformed one would turn the
    /// framework into the open redirect it exists to avoid.
    /// </summary>
    private static void ValidateInteractionPath(
        string? path,
        string optionPath,
        string code,
        ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (path is null || InteractionPath.IsSafe(path))
            return;

        failures.Add(new(
            code,
            $"AuthorizationServerOptions.{optionPath} must be an " +
            "absolute path within the host application (starting with '/'), without scheme, " +
            "authority, query, fragment, control characters, or a leading '//' or '/\\' " +
            "that a browser would resolve to another origin."));
    }
}
