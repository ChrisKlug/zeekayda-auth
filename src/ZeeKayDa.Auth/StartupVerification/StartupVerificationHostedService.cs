using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth;

/// <summary>
/// The single <see cref="IHostedService"/> that runs every framework startup check. Runs three
/// disjoint phases in one <see cref="StartAsync"/>: internal gates first (fail-fast, sequential,
/// nothing logged until every gate has passed), then <see cref="IStartupVerifier"/> instances, then
/// <see cref="IStartupActivator"/> instances. Each of the latter two runs all of its members and
/// aggregates every failure into one <see cref="ZeeKayDaConfigurationException"/> thrown once — but
/// <strong>the activator phase does not run at all if the verifier phase produced a failure</strong>,
/// so an application with a broken issuer never opens a connection to a key vault before being told
/// about the issuer. Because every phase runs inside a single <see cref="StartAsync"/> call,
/// <c>HostOptions.ServicesStartConcurrently</c> has no effect on this ordering, and because the
/// phases are disjoint collections rather than an ordering knob, no check can claim a position.
/// </summary>
internal sealed class StartupVerificationHostedService(
    IEnumerable<IStartupVerificationGate> gates,
    IServiceProvider rootServices,
    IServiceScopeFactory scopeFactory) : IHostedService
{
    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var pendingGateWarnings = new List<(object Source, string Name, StartupVerificationWarning Warning)>();

        foreach (var gate in gates)
        {
            await using var gateScope = scopeFactory.CreateAsyncScope();
            var gateContext = new StartupVerificationContext();

            // A gate's unexpected exception is discarded rather than carried: the gate phase aborts
            // on its own failure check immediately below, so there is no phase aggregate to hang it
            // on. It still reaches operators as the failure text naming the exception type.
            _ = await InvokeAsync(
                gate.Name,
                gateContext,
                ct => gate.VerifyAsync(gateContext, gateScope.ServiceProvider, ct),
                cancellationToken);

            if (gateContext.Failures.Count > 0)
            {
                // Warnings from gates that already passed are logged before aborting, rather than
                // discarded with the buffer. This is safe precisely because they are pending: a
                // warning can only be in the buffer if an earlier gate passed, and the gate that
                // establishes whether the logger can be trusted is itself a gate — so if that one
                // failed, the buffer is empty and nothing is logged.
                foreach (var (pendingSource, pendingName, pendingWarning) in pendingGateWarnings)
                    LogWarningOrThrow(pendingSource, pendingName, pendingWarning);

                throw new ZeeKayDaConfigurationException([.. gateContext.Failures]);
            }

            // Gate warnings are held until every gate has passed, because the sanitizing logger
            // is not yet known to be trustworthy.
            foreach (var warning in gateContext.Warnings)
                pendingGateWarnings.Add((gate, gate.Name, warning));
        }

        foreach (var (source, name, warning) in pendingGateWarnings)
            LogWarningOrThrow(source, name, warning);

        // IEnumerable<IStartupCheck> is resolved here rather than constructor-injected. Resolving
        // it runs every check's constructor, including third-party ones, and a constructor is free
        // to log — deferring the resolution until after the gate phase is what makes "nothing logs
        // before the gate has passed" true of check construction, not merely of check execution.
        await RunPhaseAsync(rootServices.GetServices<IStartupVerifier>(), cancellationToken)
            .ConfigureAwait(false);

        // Only reached when every verifier passed. A configuration already known to be broken never
        // reaches the checks that call into caller-supplied extension points.
        await RunPhaseAsync(rootServices.GetServices<IStartupActivator>(), cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Runs one phase to completion and throws once if anything in it failed. Every check in the
    /// phase runs even after an earlier one failed, so an operator sees every problem in that phase
    /// in one pass.
    /// </summary>
    private async Task RunPhaseAsync(IEnumerable<IStartupCheck> checks, CancellationToken cancellationToken)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();

        // An unexpected exception is recorded as a failure so the phase can continue, but its root
        // cause would then be lost — ZeeKayDaConfigurationFailure carries only strings. The
        // exceptions are collected here and travel as the aggregate's InnerException.
        var unexpected = new List<Exception>();

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
                unexpected.Add(thrown);
            }

            foreach (var warning in context.Warnings)
            {
                if (TryLogWarning(check, check.Name, warning, out var logFailureException))
                    continue;

                failures.Add(WrapWarningLogFailure(check.Name, logFailureException!));
            }

            failures.AddRange(context.Failures);
        }

        if (failures.Count == 0)
            return;

        if (unexpected.Count == 0)
            throw new ZeeKayDaConfigurationException([.. failures]);

        // The aggregate of actionable messages is what an operator must see, and the root causes of
        // any unexpected throws are what a developer needs. Both travel: the failures as
        // AggregatedFailures, the throws as InnerException.
        throw new ZeeKayDaConfigurationException(
            failures,
            unexpected.Count == 1 ? unexpected[0] : new AggregateException(unexpected));
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    // A gate warning failing to log throws immediately rather than aggregating, unlike a
    // verifier's warning-log failure below — by the time this runs, every gate has already passed
    // and the logger is exactly as trusted as it ever is. The difference is that phase 1 (gates)
    // has no failures list to defer to: each gate already aborts startup immediately on its own
    // failure, so there is no aggregation model here for a warning-log failure to join either.
    private void LogWarningOrThrow(object source, string name, StartupVerificationWarning warning)
    {
        if (!TryLogWarning(source, name, warning, out var ex))
            throw new ZeeKayDaConfigurationException(WrapWarningLogFailure(name, ex!), ex!);
    }

    // A verifier's warning.Args not matching its own MessageTemplate's placeholder count throws
    // from inside the logging framework's formatter, not from the verifier's VerifyAsync call —
    // InvokeAsync's try/catch cannot see it. Without this, one verifier's malformed warning would
    // crash startup unattributed and discard every already-aggregated genuine configuration
    // failure.
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

    // The exception TYPE is named, never ex.Message — same redaction rationale as InvokeAsync's
    // unexpected-exception branch below.
    private static ZeeKayDaConfigurationFailure WrapWarningLogFailure(string name, Exception ex) =>
        new(
            "startup.warning_log_failed",
            $"A warning produced by '{name}' could not be logged: {ex.GetType().FullName}. See " +
            "the inner exception for the root cause.");

    // Resolves ISanitizingLogger<TSource> reflectively so the entry carries the producing check's
    // own category, then forwards the template and args to the sink unformatted, so the args stay
    // structured and SecretSanitizingLogger's by-key redaction applies to them exactly as it does
    // at any other framework log call site. Only ever reached after the gate phase has passed.
    private void LogWarning(object source, string name, StartupVerificationWarning warning)
    {
        var sourceLogger = (ILogger)rootServices.GetRequiredService(
            typeof(ISanitizingLogger<>).MakeGenericType(source.GetType()));

        // ZEEKAYDA0002 requires a compile-time-constant template, because a runtime-built one
        // normally means a value has already been formatted in and is past by-key redaction. Here
        // the non-constant operand is another unformatted template, and every value still travels
        // as a structured arg, so redaction applies exactly as at a literal call site.
#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: composes a constant prefix with another unformatted template; all values stay structured args (#444)
        sourceLogger.Log(
            warning.Level,
            "[{Verifier}] {ErrorCode}: " + warning.MessageTemplate,
            [name, warning.Code, .. warning.Args]);
#pragma warning restore ZEEKAYDA0002
    }

    // Shared unexpected-exception handling for both phases. Never swallows.
    /// <summary>
    /// Invokes one check, translating what it throws into what it should have reported. Returns the
    /// unexpected exception when there was one, so the caller can carry the root cause on its phase
    /// aggregate — a failure alone cannot, since <see cref="ZeeKayDaConfigurationFailure"/> is
    /// strings only.
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
            // Orderly host shutdown during startup, not a misconfiguration. Reporting it as
            // startup.verifier_failed would fire configuration alerting on every cancelled
            // deployment. The host still does not start, so this is not a swallow.
            throw;
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            // A check that throws the framework's own configuration exception already carries
            // stable, published codes. Absorb them verbatim instead of flattening them into
            // startup.verifier_failed. AggregatedFailures is non-empty by construction, so this
            // always contributes at least one failure.
            foreach (var failure in ex.AggregatedFailures)
                context.AddFailure(failure.Code, failure.Message);
        }
        catch (Exception ex)
        {
            // Recorded, not thrown. Throwing here propagated past the phase loop and discarded every
            // failure already aggregated, so one check with a bug hid the genuine, fixable
            // configuration errors beside it and the operator found them one restart at a time.
            //
            // The exception TYPE is named, never ex.Message. An arbitrary underlying exception
            // message may carry credential material, and ZeeKayDaConfigurationFailure.Message is
            // a plain string on public API surface that SecretSanitizingLogger cannot redact. The
            // root cause stays available to operators as the phase aggregate's InnerException, where
            // the redaction wrapper does apply if it is ever logged through ISanitizingLogger<T>.
            context.AddFailure(
                "startup.verifier_failed",
                $"Verifier '{name}' threw {ex.GetType().FullName}. See the inner exception " +
                "for the root cause.");

            return ex;
        }

        return null;
    }
}
