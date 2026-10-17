namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Every bindable switch that weakens the server's security. <strong>Not for production</strong>:
/// each defaults to <see langword="false"/>, is reported at startup when on, and is fixed once
/// configuration finishes.
/// </summary>
/// <remarks>
/// Grouped so a configuration file says plainly what must not reach production:
/// <code lang="json">
/// {
///   "ZeeKayDaAuth": {
///     "Development": {
///       "AllowHttpLoopbackIssuer": true
///     }
///   }
/// }
/// </code>
/// </remarks>
public sealed class DevelopmentOptions
{
    private bool _allowHttpLoopbackIssuer;
    private bool _allowHttpLoopbackCorsOrigins;
    private bool _disableExceptionSanitizing;
    private bool _frozen;

    /// <summary>
    /// Gets or sets whether the issuer, endpoint URIs and requests may use plain HTTP on a loopback
    /// host such as <c>http://localhost:5000</c>. Any other HTTP host still fails startup, and so does an
    /// <c>https</c> issuer with this set.
    /// </summary>
    public bool AllowHttpLoopbackIssuer
    {
        get => _allowHttpLoopbackIssuer;
        set => _allowHttpLoopbackIssuer = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.Development.AllowHttpLoopbackIssuer");
    }

    /// <summary>
    /// Gets or sets whether <see cref="AuthorizationServerOptions.CorsOrigins"/> may contain HTTP
    /// loopback origins such as <c>http://localhost:3000</c>. Any other HTTP origin still fails startup.
    /// </summary>
    public bool AllowHttpLoopbackCorsOrigins
    {
        get => _allowHttpLoopbackCorsOrigins;
        set => _allowHttpLoopbackCorsOrigins = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.Development.AllowHttpLoopbackCorsOrigins");
    }

    /// <summary>
    /// Gets or sets whether exception messages, which may carry credentials, reach log sinks unredacted.
    /// </summary>
    public bool DisableExceptionSanitizing
    {
        get => _disableExceptionSanitizing;
        set => _disableExceptionSanitizing = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.Development.DisableExceptionSanitizing");
    }

    /// <summary>Refuses any later change: a switch flipped after startup would bypass its verifier.</summary>
    internal void Freeze() => _frozen = true;
}
