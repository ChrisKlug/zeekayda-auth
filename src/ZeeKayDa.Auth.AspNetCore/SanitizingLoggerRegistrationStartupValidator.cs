using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at startup that <see cref="ISanitizingLogger{T}"/> has not been shadowed by a host
/// registration, at either the open-generic or a closed-generic level.
/// </summary>
/// <remarks>
/// Two host misconfigurations can shadow the framework's open-generic
/// <c>ISanitizingLogger&lt;&gt;</c> registration: a competing open-generic registration (shadows
/// every ZeeKayDa service at once), or a closed-generic <c>ISanitizingLogger&lt;SomeType&gt;</c>
/// registration (shadows redaction only for that type — the framework never registers a closed
/// generic itself, so finding one is sufficient evidence of a shadow). Because
/// <see cref="ISanitizingLogger{T}"/> is a public extensibility surface, neither case can be ruled
/// out at compile time, so this is a hard startup failure rather than a warning: a shadowed
/// sanitizing logger silently disables the credential-redaction guarantee.
/// </remarks>
internal sealed class SanitizingLoggerRegistrationStartupValidator : IHostedService
{
    private readonly ISanitizingLogger<SanitizingLoggerRegistrationStartupValidator> _logger;
    private readonly SanitizingLoggerClosedOverrideScanner _closedOverrideScanner;

    public SanitizingLoggerRegistrationStartupValidator(
        ISanitizingLogger<SanitizingLoggerRegistrationStartupValidator> logger,
        SanitizingLoggerClosedOverrideScanner closedOverrideScanner)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(closedOverrideScanner);
        _logger = logger;
        _closedOverrideScanner = closedOverrideScanner;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();

        if (_logger is not SecretSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "logging.sanitizing_logger_shadowed",
                $"ISanitizingLogger<> resolved to {_logger.GetType().FullName}, not the " +
                "framework's own SecretSanitizingLogger<>. A registration has shadowed the " +
                "open-generic credential-redaction wrapper for every ZeeKayDa service in this " +
                "application. Remove the custom ISanitizingLogger<> registration, or register a " +
                "decorator that still forwards to the framework's own implementation."));
        }

        var closedOverrides = _closedOverrideScanner.FindClosedGenericOverrides();
        if (closedOverrides.Count > 0)
        {
            var offendingTypes = string.Join(", ", closedOverrides.Select(DescribeClosedGenericArgument));
            failures.Add(new ZeeKayDaConfigurationFailure(
                "logging.sanitizing_logger_closed_override",
                $"A closed-generic ISanitizingLogger<T> registration was found for: {offendingTypes}. " +
                "The framework only ever registers the open-generic ISanitizingLogger<>, so this can " +
                "only be a host registration that bypasses the credential-redaction wrapper for that " +
                "specific type. Remove the closed-generic registration(s)."));
        }

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static string DescribeClosedGenericArgument(Type closedSanitizingLoggerType)
    {
        var typeArgument = closedSanitizingLoggerType.GetGenericArguments()[0];
        return typeArgument.FullName ?? typeArgument.Name;
    }
}
