namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Every switch that weakens the server's security, one flag per effect. <strong>Not for
/// production</strong> — each defaults to <see langword="false"/>, and each enabled flag is
/// reported at startup.
/// </summary>
/// <remarks>
/// Not only for a developer's machine: a test host in CI may need them too. Grouping them here
/// makes a configuration file say plainly what must not reach production:
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
    /// <summary>
    /// Gets or sets a value indicating whether the server may be served over HTTP from a loopback
    /// host: an <c>http</c> loopback issuer and endpoint URIs, and plain-HTTP requests from a
    /// loopback address.
    /// </summary>
    /// <remarks>
    /// When <see langword="false"/> (the default), an HTTP issuer or endpoint URI fails startup and
    /// a non-HTTPS request is refused. When <see langword="true"/>, HTTP is accepted only for a
    /// loopback host such as <c>http://localhost:5000</c>; any other HTTP host still fails startup.
    /// </remarks>
    public bool AllowHttpLoopbackIssuer { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether <see cref="AuthorizationServerOptions.CorsOrigins"/>
    /// may contain <c>http</c> loopback origins such as <c>http://localhost:3000</c>.
    /// </summary>
    /// <remarks>
    /// When <see langword="false"/> (the default), every CORS origin must use HTTPS. When
    /// <see langword="true"/>, HTTP is accepted only for a loopback host; any other HTTP origin
    /// still fails startup.
    /// </remarks>
    public bool AllowHttpLoopbackCorsOrigins { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether exception messages reach log sinks unredacted.
    /// </summary>
    /// <remarks>
    /// When <see langword="false"/> (the default), every exception the framework logs is replaced
    /// by one whose message is a fixed placeholder, because an exception message may contain
    /// credential material. Set it to <see langword="true"/> to trade that protection for full
    /// diagnostic detail.
    /// </remarks>
    public bool DisableExceptionSanitizing { get; set; }
}
