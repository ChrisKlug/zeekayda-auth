using ZeeKayDa.Auth.Security;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Provides static header string values for <see cref="ReferrerPolicy"/> and
/// <see cref="CrossOriginResourcePolicy"/> enum values.
/// </summary>
internal static class SecurityHeaderValues
{
    /// <summary>Returns the canonical HTTP header string for the given <see cref="ReferrerPolicy"/>.</summary>
    internal static string ToHeaderValue(ReferrerPolicy policy) => policy switch
    {
        ReferrerPolicy.NoReferrer => "no-referrer",
        ReferrerPolicy.NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
        ReferrerPolicy.Origin => "origin",
        ReferrerPolicy.OriginWhenCrossOrigin => "origin-when-cross-origin",
        ReferrerPolicy.SameOrigin => "same-origin",
        ReferrerPolicy.StrictOrigin => "strict-origin",
        ReferrerPolicy.StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        ReferrerPolicy.UnsafeUrl => "unsafe-url",
        _ => throw new ArgumentOutOfRangeException(nameof(policy), policy, null)
    };

    /// <summary>Returns the canonical HTTP header string for the given <see cref="CrossOriginResourcePolicy"/>.</summary>
    internal static string ToHeaderValue(CrossOriginResourcePolicy policy) => policy switch
    {
        CrossOriginResourcePolicy.SameSite => "same-site",
        CrossOriginResourcePolicy.SameOrigin => "same-origin",
        CrossOriginResourcePolicy.CrossOrigin => "cross-origin",
        _ => throw new ArgumentOutOfRangeException(nameof(policy), policy, null)
    };
}
