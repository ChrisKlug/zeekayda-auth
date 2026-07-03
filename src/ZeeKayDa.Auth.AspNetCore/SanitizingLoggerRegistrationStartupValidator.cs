using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at startup that <see cref="ISanitizingLogger{T}"/> has not been shadowed by a host
/// registration, at either the open-generic or a closed-generic level.
/// </summary>
/// <remarks>
/// <para>
/// <c>AddZeeKayDaAuthCore()</c> registers only the open-generic <c>ISanitizingLogger&lt;&gt;</c>
/// singleton, via <c>TryAddSingleton</c>. Two distinct host misconfigurations can shadow it, and
/// this validator catches both:
/// </para>
/// <list type="number">
/// <item>A host registration for the same open-generic <c>ISanitizingLogger&lt;&gt;</c> — whether
/// added before <c>AddZeeKayDaAuth()</c> (wins the <c>TryAdd</c> race) or after via a plain
/// <c>Add</c> (wins .NET DI's "last open-generic registration wins" resolution rule) — shadows
/// every ZeeKayDa service at once, including ones the host never touches directly.</item>
/// <item>A host registration for one specific closed <c>ISanitizingLogger&lt;SomeType&gt;</c>
/// shadows redaction only for that type, regardless of registration order — .NET DI always
/// prefers an exact closed-generic match over an open-generic fallback. The framework itself never
/// registers a closed generic for this interface (see <see cref="SanitizingLoggerClosedOverrideScanner"/>),
/// so finding one is sufficient evidence of a shadow.</item>
/// </list>
/// <para>
/// Now that <see cref="ISanitizingLogger{T}"/> is a public extensibility surface (so packages such
/// as <c>ZeeKayDa.Auth.AzureKeyVault</c>, and genuine third-party providers, can accept it via
/// constructor injection without <c>InternalsVisibleTo</c> — see ADR 0011 Amendment 2(d)), neither
/// case can be ruled out at compile time.
/// </para>
/// <para>
/// This is a hard failure, not a warning. Unlike a shadowed <c>IClientRepository</c> (see
/// <see cref="ClientRepositoryStartupActivator"/>), a shadowed sanitizing logger silently
/// disables the credential-redaction guarantee described in ADR 0007 §7, so it must stop the host
/// from starting rather than merely being logged.
/// </para>
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
