using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// The single <see cref="IHostedService"/> that runs every framework startup check. Validates every
/// registered options type, then runs two phases in one <see cref="StartAsync"/>: every
/// <see cref="IStartupVerifier"/>, then every <see cref="IStartupActivator"/>. Each phase runs all of
/// its members and aggregates every failure into one <see cref="ZeeKayDaConfigurationException"/>
/// thrown once — but <strong>the activator phase does not run at all if the verifier phase produced
/// a failure</strong>, so an application with a broken issuer never opens a connection to a key
/// vault before being told about the issuer. Because every phase runs inside a single
/// <see cref="StartAsync"/> call, <c>HostOptions.ServicesStartConcurrently</c> has no effect on this
/// ordering, and because the phases are disjoint collections rather than an ordering knob, no check
/// can claim a position.
/// </summary>
internal sealed class StartupVerificationHostedService(IServiceScopeFactory scopeFactory) : IHostedService
{
    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
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

    /// <summary>
    /// Runs one phase to completion and throws once if anything in it failed. Every check in the
    /// phase runs even after an earlier one failed, so an operator sees every problem in that phase
    /// in one pass. The checks are resolved from one scope created for the phase.
    /// </summary>
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
    /// Collapses failures with the same code and message. Two checks can surface the same broken
    /// dependency — the client-repository activator and the signing key ring's own activator both
    /// report a failed key source, because each genuinely needs it initialized — and that is one
    /// problem for the operator, not two.
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
    /// Logs one warning under the producing check's own category, returning a failure when it
    /// could not be logged — a warning the operator will never see is itself a configuration
    /// problem. Malformed args throw from inside the logging framework's formatter, not from the
    /// check.
    /// </summary>
    private static ReportedFailure? TryLogWarning(
        IServiceProvider services, Check check, StartupVerificationWarning warning)
    {
        try
        {
            var logger = (ILogger)services.GetRequiredService(
                typeof(SanitizingLogger<>).MakeGenericType(check.Instance.GetType()));

            // ZEEKAYDA0002 requires a compile-time-constant template, because a runtime-built one
            // normally means a value has already been formatted in and is past by-key redaction.
            // Here the non-constant operand is another unformatted template, and every value still
            // travels as a structured arg, so redaction applies exactly as at a literal call site.
#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: composes a constant prefix with another unformatted template; all values stay structured args (#444)
            logger.Log(
                warning.Level,
                "[{Verifier}] {ErrorCode}: " + warning.MessageTemplate,
                [check.Name, warning.Code, .. warning.Args]);
#pragma warning restore ZEEKAYDA0002
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

    /// <summary>A resolved verifier or activator, adapted to the one shape the runner drives.</summary>
    private sealed record Check(
        object Instance,
        string Name,
        Func<StartupVerificationContext, CancellationToken, Task> VerifyAsync);

    /// <summary>A failure and the exception behind it, when there is one.</summary>
    private sealed record ReportedFailure(ZeeKayDaConfigurationFailure Failure, Exception? RootCause);
}
