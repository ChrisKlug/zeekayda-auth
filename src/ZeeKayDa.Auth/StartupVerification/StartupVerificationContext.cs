using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth;

/// <summary>
/// Accumulates the failures and warnings produced by a single <see cref="IStartupVerifier"/> (or
/// internal gate) invocation. The runner constructs a fresh instance for every invocation, so
/// nothing here needs to be reset between checks.
/// </summary>
public sealed class StartupVerificationContext
{
    private readonly List<ZeeKayDaConfigurationFailure> _failures = [];
    private readonly List<StartupVerificationWarning> _warnings = [];

    /// <summary>
    /// Records a configuration failure. Does not throw or abort immediately — the runner aborts
    /// startup once the current phase has finished running.
    /// </summary>
    /// <param name="code">A stable, versioned string identifier for this failure.</param>
    /// <param name="message">A human-readable description of the failure.</param>
    public void AddFailure(string code, string message) => _failures.Add(new ZeeKayDaConfigurationFailure(code, message));

    /// <summary>
    /// Records a structured warning for the runner to log. Does not abort startup.
    /// </summary>
    /// <param name="code">A stable, versioned string identifier for this warning.</param>
    /// <param name="messageTemplate">
    /// An <see cref="ILogger"/> named-placeholder template (e.g. <c>"{StoreName}"</c>) — it is
    /// passed through to the sink unformatted, exactly like any other <c>LogWarning</c> call site,
    /// so structured backends can index the fields and <c>SecretSanitizingLogger</c>'s by-key
    /// redaction can act on them.
    /// </param>
    /// <param name="level">The <see cref="LogLevel"/> the runner logs this warning at.</param>
    /// <param name="args">The structured arguments matching <paramref name="messageTemplate"/>'s placeholders, in order.</param>
    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args)
        => _warnings.Add(new StartupVerificationWarning(code, messageTemplate, level, args));

    /// <summary>
    /// Records a structured warning for the runner to log at <see cref="LogLevel.Warning"/>. Does
    /// not abort startup.
    /// </summary>
    /// <param name="code">A stable, versioned string identifier for this warning.</param>
    /// <param name="messageTemplate">
    /// An <see cref="ILogger"/> named-placeholder template (e.g. <c>"{StoreName}"</c>) — it is
    /// passed through to the sink unformatted, exactly like any other <c>LogWarning</c> call site,
    /// so structured backends can index the fields and <c>SecretSanitizingLogger</c>'s by-key
    /// redaction can act on them.
    /// </param>
    /// <param name="args">The structured arguments matching <paramref name="messageTemplate"/>'s placeholders, in order.</param>
    public void AddWarning(string code, string messageTemplate, params object?[] args)
        => AddWarning(code, messageTemplate, LogLevel.Warning, args);

    /// <summary>The failures recorded so far by this invocation.</summary>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> Failures => _failures;

    /// <summary>The warnings recorded so far by this invocation.</summary>
    public IReadOnlyList<StartupVerificationWarning> Warnings => _warnings;
}
