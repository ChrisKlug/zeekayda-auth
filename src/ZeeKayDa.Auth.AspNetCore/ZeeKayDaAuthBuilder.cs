using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// A builder for configuring ZeeKayDa.Auth services.
/// </summary>
/// <remarks>
/// Returned by <c>AddZeeKayDaAuth()</c>. Use extension methods on this builder to register
/// optional features (signing keys, client stores, etc.) without adding properties to
/// <see cref="ZeeKayDa.Auth.AuthorizationServerOptions"/>.
/// </remarks>
public sealed class ZeeKayDaAuthBuilder
{
    /// <summary>
    /// Initialises a new <see cref="ZeeKayDaAuthBuilder"/> instance.
    /// </summary>
    /// <param name="services">The application service collection.</param>
    internal ZeeKayDaAuthBuilder(IServiceCollection services)
    {
        Services = services;
    }

    /// <summary>Gets the application service collection.</summary>
    public IServiceCollection Services { get; }

    /// <summary>
    /// Disables the wrapping of exception messages by <c>SecretSanitizingLogger</c>.
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    /// <remarks>
    /// By default, <c>SecretSanitizingLogger</c> replaces each logged exception with a
    /// <c>RedactedExceptionWrapper</c> whose message is a fixed placeholder. This prevents
    /// exception messages — which may contain credential material — from reaching log sinks.
    /// Call this method only when the downstream log sink is itself responsible for redaction.
    /// A startup warning (escalated to <c>Error</c> in production) is emitted when this opt-out
    /// is active.
    /// </remarks>
    public ZeeKayDaAuthBuilder DisableExceptionSanitizing()
    {
        Services.Configure<SecretSanitizingLoggerOptions>(o => o.ExceptionSanitizingDisabled = true);
        Services.AddHostedService<ExceptionSanitizingDisabledWarningService>();
        return this;
    }
}
