namespace ZeeKayDa.Auth.Security;

/// <summary>The defensive security headers applied to every ZeeKayDa.Auth protocol endpoint response.</summary>
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
    /// Defaults to <see cref="CrossOriginResourcePolicy.SameOrigin"/>.
    /// </summary>
    /// <remarks>
    /// Browser libraries such as <c>oidc-client-ts</c> fetch discovery and JWKS cross-origin, so a
    /// deployment serving browser clients sets <see cref="CrossOriginResourcePolicy.CrossOrigin"/>.
    /// </remarks>
    public CrossOriginResourcePolicy CrossOriginResourcePolicy { get; set; } = CrossOriginResourcePolicy.SameOrigin;
}
