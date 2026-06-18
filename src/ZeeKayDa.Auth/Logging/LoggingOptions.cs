namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Framework-behavior options that control how ZeeKayDa.Auth emits log entries.
/// </summary>
/// <remarks>
/// This is a framework-behavior group on <see cref="ZeeKayDa.Auth.AuthorizationServerOptions"/>,
/// following the convention established in ADR 0002 §5 and the 2026-06-13 framework-behavior-groups
/// amendment. Settings here govern the framework's own runtime logging behavior and have no
/// OIDC Discovery document analogue.
/// </remarks>
public sealed class LoggingOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether exception message sanitization is disabled.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see langword="false"/> (the default), <c>SecretSanitizingLogger</c> wraps every
    /// logged exception in a <c>RedactedExceptionWrapper</c> whose message is a fixed placeholder.
    /// This prevents exception messages — which may contain credential material — from reaching
    /// log sinks.
    /// </para>
    /// <para>
    /// Set this to <see langword="true"/> only in development environments where credential
    /// exposure in logs is acceptable in exchange for full diagnostic detail. A startup warning
    /// is emitted whenever this flag is enabled to make the risk visible and intentional. This
    /// setting can be applied via <c>appsettings.Development.json</c>:
    /// <code lang="json">
    /// {
    ///   "ZeeKayDaAuth": {
    ///     "Logging": {
    ///       "DisableExceptionSanitizing": true
    ///     }
    ///   }
    /// }
    /// </code>
    /// </para>
    /// </remarks>
    public bool DisableExceptionSanitizing { get; set; }
}
