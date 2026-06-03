namespace ZeeKayDa.Auth;

/// <summary>
/// Configuration options for defensive security headers applied to all ZeeKayDa.Auth protocol
/// endpoint responses.
/// </summary>
public sealed class SecurityHeadersOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether <c>X-Content-Type-Options: nosniff</c> is emitted.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool ContentTypeOptionsNoSniff { get; set; } = true;

    /// <summary>
    /// Gets or sets the value for the <c>Referrer-Policy</c> header.
    /// Defaults to <see cref="ReferrerPolicy.NoReferrer"/>.
    /// </summary>
    public ReferrerPolicy ReferrerPolicy { get; set; } = ReferrerPolicy.NoReferrer;

    /// <summary>
    /// Gets or sets the value for the <c>Cross-Origin-Resource-Policy</c> header.
    /// Defaults to <see cref="CrossOriginResourcePolicy.CrossOrigin"/>.
    /// </summary>
    public CrossOriginResourcePolicy CrossOriginResourcePolicy { get; set; } = CrossOriginResourcePolicy.CrossOrigin;
}
