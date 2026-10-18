using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Security;

/// <summary>The defensive security headers applied to every ZeeKayDa.Auth protocol endpoint response.</summary>
public sealed class SecurityHeadersOptions
{
    private bool _contentTypeOptionsNoSniff = true;
    private ReferrerPolicy _referrerPolicy = ReferrerPolicy.NoReferrer;
    private CrossOriginResourcePolicy _crossOriginResourcePolicy = CrossOriginResourcePolicy.SameOrigin;
    private bool _frozen;

    /// <summary>
    /// Gets or sets a value indicating whether <c>X-Content-Type-Options: nosniff</c> is emitted.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool ContentTypeOptionsNoSniff
    {
        get => _contentTypeOptionsNoSniff;
        set => _contentTypeOptionsNoSniff = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.SecurityHeaders.ContentTypeOptionsNoSniff");
    }

    /// <summary>
    /// Gets or sets the value for the <c>Referrer-Policy</c> header.
    /// Defaults to <see cref="ReferrerPolicy.NoReferrer"/>.
    /// </summary>
    public ReferrerPolicy ReferrerPolicy
    {
        get => _referrerPolicy;
        set => _referrerPolicy = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.SecurityHeaders.ReferrerPolicy");
    }

    /// <summary>
    /// Gets or sets the value for the <c>Cross-Origin-Resource-Policy</c> header.
    /// Defaults to <see cref="CrossOriginResourcePolicy.SameOrigin"/>.
    /// </summary>
    /// <remarks>
    /// Browser libraries such as <c>oidc-client-ts</c> fetch discovery and JWKS cross-origin, so a
    /// deployment serving browser clients sets <see cref="CrossOriginResourcePolicy.CrossOrigin"/>.
    /// </remarks>
    public CrossOriginResourcePolicy CrossOriginResourcePolicy
    {
        get => _crossOriginResourcePolicy;
        set => _crossOriginResourcePolicy = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.SecurityHeaders.CrossOriginResourcePolicy");
    }

    /// <summary>Refuses any later change to these options.</summary>
    internal void Freeze() => _frozen = true;
}
