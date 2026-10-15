using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth;

// The rules that read more than one options group, each named by its topic.
internal static partial class AuthorizationServerOptionsValidation
{
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateLifetimeRelationships(AuthorizationServerOptions options)
    {
        // The code tombstone lives for the refresh token lifetime; a shorter one lets a late replay escape revocation.
        if (RefreshTokensExpireBeforeCodes(options))
        {
            yield return new(
                "configuration.token_endpoint.refresh_token_lifetime.shorter_than_code_lifetime",
                "AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime must be greater than or equal to " +
                "AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime to ensure tombstone " +
                "retention covers the authorization code validity window.");
        }

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

    /// <summary>Both lifetimes positive, so a non-positive one is reported only by its own group.</summary>
    private static bool RefreshTokensExpireBeforeCodes(AuthorizationServerOptions options) =>
        options.TokenEndpoint.RefreshTokenLifetime > TimeSpan.Zero
        && options.AuthorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.Zero
        && options.TokenEndpoint.RefreshTokenLifetime < options.AuthorizationEndpoint.AuthorizationCodeLifetime;

    /// <summary>Both values in range, so an out-of-range one is reported only by its own rule.</summary>
    private static bool ClockSkewReachesHalfTheCodeLifetime(AuthorizationServerOptions options) =>
        options.ClockSkewTolerance >= TimeSpan.Zero
        && options.AuthorizationEndpoint.AuthorizationCodeLifetime > TimeSpan.Zero
        && options.ClockSkewTolerance >= options.AuthorizationEndpoint.AuthorizationCodeLifetime / 2;

    /// <summary>
    /// A new key reaches a relying party up to one refresh interval plus one JWKS cache lifetime after
    /// listing, so the lead time must cover both.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateSigningKeyLeadTime(AuthorizationServerOptions options)
    {
        var signingKeys = options.SigningKeys;
        if (signingKeys.LeadTime <= TimeSpan.Zero || signingKeys.RefreshInterval < SigningKeyOptions.MinimumRefreshInterval)
            yield break;

        var unknownFor = TokenLifetimes.Sum(options.JwksEndpoint.CacheMaxAge, signingKeys.RefreshInterval);
        if (signingKeys.LeadTime < unknownFor)
        {
            yield return new(
                "configuration.signing_keys.lead_time.shorter_than_jwks_cache_max_age_plus_refresh_interval",
                $"AuthorizationServerOptions.SigningKeys.LeadTime ({signingKeys.LeadTime}) is shorter than " +
                $"AuthorizationServerOptions.JwksEndpoint.CacheMaxAge ({options.JwksEndpoint.CacheMaxAge}) plus " +
                $"AuthorizationServerOptions.SigningKeys.RefreshInterval ({signingKeys.RefreshInterval}). A relying " +
                "party may still be serving a cached key set without the new key when it starts signing.");
        }
    }

    /// <summary>The token endpoint enforces S256, so serving the code grant without advertising it misleads clients.</summary>
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
