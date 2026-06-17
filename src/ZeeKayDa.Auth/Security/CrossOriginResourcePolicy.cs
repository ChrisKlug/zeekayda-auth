namespace ZeeKayDa.Auth.Security;

/// <summary>
/// Values for the <c>Cross-Origin-Resource-Policy</c> HTTP response header.
/// </summary>
public enum CrossOriginResourcePolicy
{
    /// <summary><c>same-site</c></summary>
    SameSite,
    /// <summary><c>same-origin</c></summary>
    SameOrigin,
    /// <summary><c>cross-origin</c></summary>
    CrossOrigin
}
