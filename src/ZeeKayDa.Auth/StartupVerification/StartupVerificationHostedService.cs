using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth;

/// <summary>
/// The single <see cref="IHostedService"/> that runs every framework startup check, in three phases:
/// internal gates, then <see cref="IStartupVerifier"/>s, then <see cref="IStartupActivator"/>s.
/// </summary>
internal sealed class StartupVerificationHostedService(
    IEnumerable<IStartupVerificationGate> gates,
    IServiceProvider rootServices,
    IServiceScopeFactory scopeFactory) : IHostedService
{
    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await RunGatePhaseAsync(cancellationToken).ConfigureAwait(false);

        // The checks are resolved here, not injected: a check's constructor may log, and nothing may
        // log before the gates have passed.
        RejectChecksRegisteredAsTheBaseInterface();

        await RunPhaseOrThrowAsync(rootServices.GetServices<IStartupVerifier>(), cancellationToken)
            .ConfigureAwait(false);

        await RunPhaseOrThrowAsync(rootServices.GetServices<IStartupActivator>(), cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Runs every gate, aborting on the first that fails. Gate warnings are held back until the
    /// sanitizing logger has been verified.
    /// </summary>
    private async Task RunGatePhaseAsync(CancellationToken cancellationToken)
    {
        var pendingWarnings = new List<(object Source, string Name, StartupVerificationWarning Warning)>();
        var sanitizingLoggerVerified = false;

        foreach (var gate in gates)
        {
            await using var gateScope = scopeFactory.CreateAsyncScope();
            var context = new StartupVerificationContext();

            var thrown = await InvokeAsync(
                gate.Name,
                context,
                ct => gate.VerifyAsync(context, gateScope.ServiceProvider, ct),
                cancellationToken);

            if (context.Failures.Count > 0)
                throw AbortGatePhase(context, thrown, sanitizingLoggerVerified, pendingWarnings);

            sanitizingLoggerVerified |= gate is SanitizingLoggerRegistrationGate;

            foreach (var warning in context.Warnings)
                pendingWarnings.Add((gate, gate.Name, warning));
        }

        foreach (var (source, name, warning) in pendingWarnings)
            LogWarningOrThrow(source, name, warning);
    }

    /// <summary>
    /// Builds the exception that aborts the gate phase, first logging the warnings of gates that
    /// already passed, if the logger is known good.
    /// </summary>
    private ZeeKayDaConfigurationException AbortGatePhase(
        StartupVerificationContext context,
        Exception? thrown,
        bool sanitizingLoggerVerified,
        List<(object Source, string Name, StartupVerificationWarning Warning)> pendingWarnings)
    {
        if (sanitizingLoggerVerified)
        {
            foreach (var (source, name, warning) in pendingWarnings)
                LogWarningOrThrow(source, name, warning);
        }

        return thrown is null
            ? new ZeeKayDaConfigurationException([.. context.Failures])
            : new ZeeKayDaConfigurationException([.. context.Failures], thrown);
    }

    /// <summary>
    /// Logs one check's warnings, returning a failure for each that could not be logged.
    /// </summary>
    private IEnumerable<ZeeKayDaConfigurationFailure> LogWarnings(
        IStartupCheck check, StartupVerificationContext context)
    {
        foreach (var warning in context.Warnings)
        {
            if (!TryLogWarning(check, check.Name, warning, out var logFailureException))
                yield return WrapWarningLogFailure(check.Name, logFailureException!);
        }
    }

    /// <summary>
    /// Fails startup for a check registered as <see cref="IStartupCheck"/> itself: the container
    /// never resolves a derived registration for a base service type, so it would silently never run.
    /// </summary>
    private void RejectChecksRegisteredAsTheBaseInterface()
    {
        var misregistered = rootServices.GetServices<IStartupCheck>().ToArray();
        if (misregistered.Length == 0)
            return;

        throw new ZeeKayDaConfigurationException(
            [.. misregistered.Select(check => new ZeeKayDaConfigurationFailure(
                "startup.check_registered_as_base_interface",
                $"'{check.GetType().FullName}' is registered as {nameof(IStartupCheck)}, which the " +
                $"runner never enumerates, so it would never run. Register it as " +
                $"{nameof(IStartupVerifier)} if it only reads options or inspects the container, or " +
                $"as {nameof(IStartupActivator)} if it calls into a caller-supplied extension point."))]);
    }

    /// <summary>
    /// Runs every check in the phase, even after one has failed, then throws once with every failure.
    /// </summary>
    private async Task RunPhaseOrThrowAsync(IEnumerable<IStartupCheck> checks, CancellationToken cancellationToken)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();

        // A failure cannot carry an exception, so the root causes travel separately, as the
        // aggregate's InnerException.
        var rootCauses = new List<Exception>();

        foreach (var check in checks)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var context = new StartupVerificationContext();

            if (await InvokeAsync(
                    check.Name,
                    context,
                    ct => check.VerifyAsync(context, scope.ServiceProvider, ct),
                    cancellationToken) is { } thrown)
            {
                rootCauses.Add(thrown);
            }

            failures.AddRange(LogWarnings(check, context));
            failures.AddRange(context.Failures);
        }

        // Two checks can surface the same broken dependency, such as a failed key source; it is one
        // problem, reported once.
        failures = [.. failures.DistinctBy(failure => (failure.Code, failure.Message))];

        if (failures.Count == 0)
            return;

        if (rootCauses.Count == 0)
            throw new ZeeKayDaConfigurationException([.. failures]);

        throw new ZeeKayDaConfigurationException(
            failures,
            rootCauses.Count == 1 ? rootCauses[0] : new AggregateException(rootCauses));
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    // Gates have no failure list to join, so a gate warning that cannot be logged aborts at once.
    private void LogWarningOrThrow(object source, string name, StartupVerificationWarning warning)
    {
        if (!TryLogWarning(source, name, warning, out var ex))
            throw new ZeeKayDaConfigurationException(WrapWarningLogFailure(name, ex!), ex!);
    }

    // A template whose placeholders do not match its args throws from the log formatter, outside
    // InvokeAsync's try. Caught so it is attributed to its check and does not discard the phase's
    // other failures.
    private bool TryLogWarning(
        object source, string name, StartupVerificationWarning warning, out Exception? exception)
    {
        try
        {
            LogWarning(source, name, warning);
            exception = null;
            return true;
        }
        catch (Exception ex)
        {
            exception = ex;
            return false;
        }
    }

    private static ZeeKayDaConfigurationFailure WrapWarningLogFailure(string name, Exception ex) =>
        new(
            "startup.warning_log_failed",
            $"A warning produced by '{name}' could not be logged: {DescribeWithoutMessage(ex)}. See " +
            "the inner exception for the root cause.");

    // Logged under the check's own category, with the template and args unformatted, so by-key
    // redaction applies exactly as at any other call site.
    private void LogWarning(object source, string name, StartupVerificationWarning warning)
    {
        var sourceLogger = (ILogger)rootServices.GetRequiredService(
            typeof(ISanitizingLogger<>).MakeGenericType(source.GetType()));

        // The template is not a constant, but its non-constant part is another unformatted
        // template, and every value still travels as a structured arg.
#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: composes a constant prefix with another unformatted template; all values stay structured args (#444)
        sourceLogger.Log(
            warning.Level,
            "[{Verifier}] {ErrorCode}: " + warning.MessageTemplate,
            [name, warning.Code, .. warning.Args]);
#pragma warning restore ZEEKAYDA0002
    }

    /// <summary>
    /// Names an exception by its type, never its message: a message may carry credential material,
    /// and a failure's text is public and cannot be redacted.
    /// </summary>
    private static string? DescribeWithoutMessage(Exception ex) => ex.GetType().FullName;

    /// <summary>
    /// Invokes one check, recording what it throws as failures, and returns the root cause behind
    /// the throw, if any.
    /// </summary>
    private static async ValueTask<Exception?> InvokeAsync(
        string name,
        StartupVerificationContext context,
        Func<CancellationToken, ValueTask> invoke,
        CancellationToken cancellationToken)
    {
        try
        {
            await invoke(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // A host shutting down during startup is not a misconfiguration, and must not fire
            // configuration alerting.
            throw;
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            // Absorbed verbatim, so the check's stable codes survive.
            foreach (var failure in ex.AggregatedFailures)
                context.AddFailure(failure.Code, failure.Message);

            return ex.InnerException;
        }
        catch (Exception ex)
        {
            // Recorded rather than thrown, so a buggy check cannot hide the failures beside it.
            context.AddFailure(
                "startup.verifier_failed",
                $"Check '{name}' threw {DescribeWithoutMessage(ex)}. See the inner exception " +
                "for the root cause.");

            return ex;
        }

        return null;
    }
}
