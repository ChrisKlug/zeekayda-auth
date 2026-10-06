using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth;

// The rules that read more than one options group, each named by its topic.
internal static partial class AuthorizationServerOptionsValidation
{
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateLifetimeRelationships(AuthorizationServerOptions options)
    {
        // The authorization code tombstone is kept for the refresh token lifetime, so it must cover
        // the code's whole validity window — otherwise a delayed code replay could escape the
        // RFC 9700 §2.1.1 family-revocation mandate.
        if (RefreshTokensExpireBeforeCodes(options))
        {
            yield return new(
                "configuration.token_endpoint.refresh_token_lifetime.shorter_than_code_lifetime",
                "AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime must be greater than or equal to " +
                "AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime to ensure tombstone " +
                "retention covers the authorization code validity window.");
        }

        // A tolerance this large extends the acceptance window past the code's intended expiry,
        // undermining the short-lived code guarantee of RFC 9700 §2.1.1.
        if (ClockSkewReachesHalfTheCodeLifetime(options))
        {
            var halfCodeLifetime = options.AuthorizationEndpoint.AuthorizationCodeLifetime / 2;
            yield return new(
                "configuration.clock_skew_tolerance.too_large",
                $"AuthorizationServerOptions.ClockSkewTolerance ({options.ClockSkewTolerance}) is greater than or " +
                $"equal to half of AuthorizationCodeLifetime ({halfCodeLifetime}). A tolerance this large effectively " +
                "extends the authorization code acceptance window past its intended expiry.");
        }
    }

    /// <summary>
    /// Both lifetimes positive, and the refresh token's shorter than the code's. A non-positive
    /// lifetime is reported by its own group, so it is not also reported here.
    /// </summary>
    private static bool RefreshTokensExpireBeforeCodes(AuthorizationServerOptions options) =>
        options.TokenEndpoint.RefreshTokenLifetime > TimeSpan.Zero
        && options.AuthorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.Zero
        && options.TokenEndpoint.RefreshTokenLifetime < options.AuthorizationEndpoint.AuthorizationCodeLifetime;

    /// <summary>
    /// A non-negative tolerance of at least half a positive code lifetime. A negative tolerance or a
    /// non-positive lifetime is reported by its own rule, so it is not also reported here.
    /// </summary>
    private static bool ClockSkewReachesHalfTheCodeLifetime(AuthorizationServerOptions options) =>
        options.ClockSkewTolerance >= TimeSpan.Zero
        && options.AuthorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.Zero
        && options.ClockSkewTolerance >= options.AuthorizationEndpoint.AuthorizationCodeLifetime / 2;

    /// <summary>
    /// A relying party may serve the key set from its cache for up to the JWKS cache lifetime, so a
    /// new key published for less than that may still be unknown to it when it starts signing.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateSigningKeyLeadTime(AuthorizationServerOptions options)
    {
        if (options.SigningKeys.LeadTime >= TimeSpan.Zero && options.SigningKeys.LeadTime < options.JwksEndpoint.CacheMaxAge)
        {
            yield return new(
                "configuration.signing_keys.lead_time.shorter_than_jwks_cache_max_age",
                $"AuthorizationServerOptions.SigningKeys.LeadTime ({options.SigningKeys.LeadTime}) is shorter than " +
                $"AuthorizationServerOptions.JwksEndpoint.CacheMaxAge ({options.JwksEndpoint.CacheMaxAge}). A relying " +
                "party may still be serving a cached key set without the new key when it starts signing.");
        }
    }

    /// <summary>
    /// PKCE with S256 is what makes the authorization code grant safe to serve (RFC 9700 §2.1.1),
    /// and the token endpoint enforces exactly that method; serving the grant without advertising
    /// it would tell clients the control is absent while relying on it.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidatePkceMatchesTheCodeGrant(AuthorizationServerOptions options)
    {
        var servesCodeGrantWithoutS256 = options.GrantTypesSupported is { } grants
            && grants.Contains(GrantType.AuthorizationCode)
            && options.AuthorizationEndpoint.CodeChallengeMethodsSupported?.Contains(CodeChallengeMethod.S256) != true;

        if (servesCodeGrantWithoutS256)
        {
            yield return new(
                "configuration.authorization_endpoint.code_challenge_methods_supported.s256_missing",
                "AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported must " +
                "contain CodeChallengeMethod.S256 when GrantTypesSupported contains GrantType.AuthorizationCode. " +
                "PKCE with S256 is mandatory for the authorization code grant (OAuth 2.1 §4.1.1, RFC 9700 §2.1.1) " +
                "and the token endpoint enforces it for every client.");
        }
    }
}
