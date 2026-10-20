using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Runs every startup check: options validation, then all verifiers, then all activators, each
/// phase reporting every failure at once and stopping the next.
/// </summary>
internal sealed class StartupVerificationHostedService(
    IServiceScopeFactory scopeFactory,
    ServiceLifetimeScanner registrations) : IHostedService
{
    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        StartupCheckLifetimes.ThrowIfAnyNotScoped(registrations);

        // Every check reads options, and none can be trusted against options that do not validate.
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            try
            {
                ValidatedOptionsCheck.ThrowIfAnyInvalid(scope.ServiceProvider);
            }
            catch (Exception ex) when (ex is not ZeeKayDaConfigurationException && !IsShutdown(ex, cancellationToken))
            {
                throw Aggregate([.. Translate(ex, "Validating the options")]);
            }
        }

        await RunPhaseAsync(
            "verifiers",
            services => services.GetServices<IStartupVerifier>()
                .Select(verifier => new Check(verifier, verifier.Name, verifier.VerifyAsync)),
            cancellationToken).ConfigureAwait(false);

        await RunPhaseAsync(
            "activators",
            services => services.GetServices<IStartupActivator>()
                .Select(activator => new Check(activator, activator.Name, activator.VerifyAsync)),
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Runs every check in one phase, then throws once if any failed.</summary>
    private async Task RunPhaseAsync(
        string phase,
        Func<IServiceProvider, IEnumerable<Check>> resolveChecks,
        CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var failures = new List<ReportedFailure>();
        var warnings = new List<(Check Check, StartupVerificationWarning Warning)>();

        List<Check> checks;
        try
        {
            checks = [.. resolveChecks(scope.ServiceProvider)];
        }
        catch (Exception ex) when (!IsShutdown(ex, cancellationToken))
        {
            failures.AddRange(Translate(ex, $"Constructing the startup {phase}"));
            checks = [];
        }

        foreach (var check in checks)
        {
            var context = new StartupVerificationContext();
            try
            {
                await check.VerifyAsync(context, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (!IsShutdown(ex, cancellationToken))
            {
                failures.AddRange(Translate(ex, $"Check '{check.Name}'"));
            }

            failures.AddRange(context.Failures.Select(failure => new ReportedFailure(failure, null)));
            warnings.AddRange(context.Warnings.Select(warning => (check, warning)));
        }

        foreach (var (check, warning) in warnings)
        {
            if (TryLogWarning(scope.ServiceProvider, check, warning) is { } logFailure)
                failures.Add(logFailure);
        }

        if (failures.Count > 0)
            throw Aggregate(failures);
    }

    private static ZeeKayDaConfigurationException Aggregate(List<ReportedFailure> failures) =>
        ZeeKayDaConfigurationException.WithRootCauses(
            ReportEachProblemOnce(failures),
            [.. failures.Select(failure => failure.RootCause).OfType<Exception>().Distinct()]);

    /// <summary>
    /// Collapses failures with the same code and message, such as a broken key source reported by
    /// two activators that both need it.
    /// </summary>
    private static ZeeKayDaConfigurationFailure[] ReportEachProblemOnce(List<ReportedFailure> failures) =>
        [.. failures.Select(failure => failure.Failure).DistinctBy(failure => (failure.Code, failure.Message))];

    // Orderly host shutdown during startup, not a misconfiguration: reporting it as a failure would
    // fire configuration alerting on every cancelled deployment. The host still does not start.
    private static bool IsShutdown(Exception ex, CancellationToken cancellationToken) =>
        ex is OperationCanceledException && cancellationToken.IsCancellationRequested;

    /// <summary>
    /// Turns what a check threw into what it should have reported, each failure paired with the
    /// root cause behind it.
    /// </summary>
    private static IEnumerable<ReportedFailure> Translate(Exception ex, string thrower)
    {
        // A configuration exception already carries stable, published codes, so they are kept
        // verbatim; its own root cause, if any, is what its messages point the reader at.
        if (ex is ZeeKayDaConfigurationException coded)
            return coded.AggregatedFailures.Select(failure => new ReportedFailure(failure, coded.InnerException));

        // The exception TYPE is named, never ex.Message: an arbitrary message may carry credential
        // material, and a failure's message is public text no redaction control can reach.
        return
        [
            new ReportedFailure(
                new ZeeKayDaConfigurationFailure(
                    "startup.verifier_failed",
                    $"{thrower} threw {ex.GetType().FullName}. See the inner exception for the root cause."),
                ex),
        ];
    }

    /// <summary>
    /// Logs one warning under the check's own category, or returns a failure when it could not be
    /// logged: a warning the operator never sees is itself a configuration problem.
    /// </summary>
    private static ReportedFailure? TryLogWarning(
        IServiceProvider services, Check check, StartupVerificationWarning warning)
    {
        try
        {
            LogWarning(services, check.Instance, check.Name, warning);
            return null;
        }
        catch (Exception ex)
        {
            return new ReportedFailure(
                new ZeeKayDaConfigurationFailure(
                    "startup.warning_log_failed",
                    $"A warning produced by '{check.Name}' could not be logged: {ex.GetType().FullName}. " +
                    "See the inner exception for the root cause."),
                ex);
        }
    }

    /// <summary>
    /// Logs one warning under <paramref name="check"/>'s own category. Also called by the one check
    /// that must run after the runner, once the host's pipeline is built.
    /// </summary>
    internal static void LogWarning(
        IServiceProvider services, object check, string checkName, StartupVerificationWarning warning)
    {
        var logger = (ILogger)services.GetRequiredService(
            typeof(SanitizingLogger<>).MakeGenericType(check.GetType()));

#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: composes a constant prefix with another unformatted template; all values stay structured args (#444)
        logger.Log(
            warning.Level,
            "[{Verifier}] {ErrorCode}: " + warning.MessageTemplate,
            [checkName, warning.Code, .. warning.Args]);
#pragma warning restore ZEEKAYDA0002
    }

    /// <summary>A resolved verifier or activator, adapted to the one shape the runner drives.</summary>
    private sealed record Check(
        object Instance,
        string Name,
        Func<StartupVerificationContext, CancellationToken, Task> VerifyAsync);

    /// <summary>A failure and the exception behind it, when there is one.</summary>
    private sealed record ReportedFailure(ZeeKayDaConfigurationFailure Failure, Exception? RootCause);
}
