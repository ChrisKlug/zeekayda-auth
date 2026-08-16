using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth;

/// <summary>
/// The single <see cref="IHostedService"/> that runs every framework startup check. Runs two
/// disjoint phases in one <see cref="StartAsync"/>: internal gates first (fail-fast, sequential,
/// nothing logged until every gate has passed), then public <see cref="IStartupVerifier"/>
/// instances (run all, aggregate every failure into one <see cref="ZeeKayDaConfigurationException"/>
/// thrown once). Because both phases run inside a single <see cref="StartAsync"/> call,
/// <c>HostOptions.ServicesStartConcurrently</c> has no effect on this ordering.
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

            await InvokeAsync(
                gate.Name,
                gateContext,
                ct => gate.VerifyAsync(gateContext, gateScope.ServiceProvider, ct),
                cancellationToken);

            if (gateContext.Failures.Count > 0)
                throw new ZeeKayDaConfigurationException([.. gateContext.Failures]);

            // Gate warnings are held until every gate has passed, because the sanitizing logger
            // is not yet known to be trustworthy.
            pendingGateWarnings.AddRange(gateContext.Warnings.Select(w => ((object)gate, gate.Name, w)));
        }

        foreach (var (source, name, warning) in pendingGateWarnings)
            LogWarning(source, name, warning);

        // IEnumerable<IStartupVerifier> is resolved here rather than constructor-injected.
        // Resolving it runs every verifier's constructor, including third-party ones, and a
        // constructor is free to log — deferring the resolution until after the gate phase is
        // what makes "nothing logs before the gate has passed" true of verifier construction, not
        // merely of verifier execution.
        var verifiers = rootServices.GetServices<IStartupVerifier>();

        var failures = new List<ZeeKayDaConfigurationFailure>();

        foreach (var verifier in verifiers)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var context = new StartupVerificationContext();

            await InvokeAsync(
                verifier.Name,
                context,
                ct => verifier.VerifyAsync(context, scope.ServiceProvider, ct),
                cancellationToken);

            foreach (var warning in context.Warnings)
                LogWarning(verifier, verifier.Name, warning);

            failures.AddRange(context.Failures);
        }

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

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
    private static async ValueTask InvokeAsync(
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
            // The exception TYPE is named, never ex.Message. An arbitrary underlying exception
            // message may carry credential material, and ZeeKayDaConfigurationFailure.Message is
            // a plain string on public API surface that SecretSanitizingLogger cannot redact. The
            // root cause stays available to operators as InnerException, where the redaction
            // wrapper does apply if it is ever logged through ISanitizingLogger<T>.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "startup.verifier_failed",
                    $"Verifier '{name}' threw {ex.GetType().FullName}. See the inner exception " +
                    "for the root cause."),
                ex);
        }
    }
}
