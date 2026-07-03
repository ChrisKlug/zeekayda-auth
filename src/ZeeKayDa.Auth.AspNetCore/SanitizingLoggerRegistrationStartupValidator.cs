using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at startup that the registered <see cref="ISanitizingLogger{T}"/> is the framework's
/// own <see cref="SecretSanitizingLogger{T}"/> and has not been shadowed by a host registration.
/// </summary>
/// <remarks>
/// <para>
/// <c>AddZeeKayDaAuthCore()</c> registers <c>ISanitizingLogger&lt;&gt;</c> as an open-generic
/// singleton via <c>TryAddSingleton</c>. A host that registers its own
/// <c>ISanitizingLogger&lt;&gt;</c> implementation before calling <c>AddZeeKayDaAuth()</c> wins
/// that <c>TryAdd</c> race and silently shadows the framework's redaction wrapper for every
/// ZeeKayDa service — including ones the host never touches directly. Now that
/// <see cref="ISanitizingLogger{T}"/> is a public extensibility surface (so packages such as
/// <c>ZeeKayDa.Auth.AzureKeyVault</c>, and genuine third-party providers, can accept it via
/// constructor injection without <c>InternalsVisibleTo</c> — see ADR 0011 Amendment 2(d)), this
/// can no longer be ruled out at compile time and must be checked at startup instead.
/// </para>
/// <para>
/// This is a hard failure, not a warning. Unlike a shadowed <c>IClientRepository</c> (see
/// <see cref="ClientRepositoryStartupActivator"/>), a shadowed sanitizing logger silently
/// disables the credential-redaction guarantee described in ADR 0007 §7 for the entire
/// application, so it must stop the host from starting rather than merely being logged.
/// </para>
/// </remarks>
internal sealed class SanitizingLoggerRegistrationStartupValidator : IHostedService
{
    private readonly ISanitizingLogger<SanitizingLoggerRegistrationStartupValidator> _logger;

    public SanitizingLoggerRegistrationStartupValidator(
        ISanitizingLogger<SanitizingLoggerRegistrationStartupValidator> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_logger is not SecretSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "logging.sanitizing_logger_shadowed",
                    $"ISanitizingLogger<> resolved to {_logger.GetType().FullName}, not the " +
                    "framework's own SecretSanitizingLogger<>. A registration made before " +
                    "AddZeeKayDaAuth() has shadowed the credential-redaction wrapper for every " +
                    "ZeeKayDa service in this application. Remove the custom ISanitizingLogger<> " +
                    "registration, or register a decorator after AddZeeKayDaAuth() that still " +
                    "forwards to the framework's own implementation."));
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
