namespace ZeeKayDa.Auth.Security;

/// <summary>
/// An out-of-range enum cast fails at startup like every other misconfiguration, rather than as a
/// 500 at request time.
/// </summary>
internal static class SecurityHeadersOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this SecurityHeadersOptions securityHeaders)
    {
        if (!Enum.IsDefined(securityHeaders.ReferrerPolicy))
        {
            yield return new(
                "configuration.security_headers.referrer_policy.undefined_value",
                $"AuthorizationServerOptions.SecurityHeaders.ReferrerPolicy value " +
                $"'{(int)securityHeaders.ReferrerPolicy}' is not a valid {nameof(ReferrerPolicy)} enum member.");
        }

        if (!Enum.IsDefined(securityHeaders.CrossOriginResourcePolicy))
        {
            yield return new(
                "configuration.security_headers.cross_origin_resource_policy.undefined_value",
                $"AuthorizationServerOptions.SecurityHeaders.CrossOriginResourcePolicy value " +
                $"'{(int)securityHeaders.CrossOriginResourcePolicy}' is not a valid {nameof(CrossOriginResourcePolicy)} enum member.");
        }
    }
}
