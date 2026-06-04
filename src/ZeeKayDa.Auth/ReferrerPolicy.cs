namespace ZeeKayDa.Auth;

/// <summary>
/// Values for the <c>Referrer-Policy</c> HTTP response header.
/// </summary>
public enum ReferrerPolicy
{
    /// <summary><c>no-referrer</c></summary>
    NoReferrer,
    /// <summary><c>no-referrer-when-downgrade</c></summary>
    NoReferrerWhenDowngrade,
    /// <summary><c>origin</c></summary>
    Origin,
    /// <summary><c>origin-when-cross-origin</c></summary>
    OriginWhenCrossOrigin,
    /// <summary><c>same-origin</c></summary>
    SameOrigin,
    /// <summary><c>strict-origin</c></summary>
    StrictOrigin,
    /// <summary><c>strict-origin-when-cross-origin</c></summary>
    StrictOriginWhenCrossOrigin,
    /// <summary><c>unsafe-url</c></summary>
    UnsafeUrl
}
