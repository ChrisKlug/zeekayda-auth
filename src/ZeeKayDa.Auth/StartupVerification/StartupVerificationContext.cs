using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// The failures and warnings from one <see cref="IStartupVerifier"/> or <see cref="IStartupActivator"/> invocation.
/// </summary>
public sealed class StartupVerificationContext
{
    private readonly List<ZeeKayDaConfigurationFailure> _failures = [];
    private readonly List<StartupVerificationWarning> _warnings = [];

    /// <summary>Records a failure; the runner aborts startup once the current phase finishes.</summary>
    /// <param name="code">A stable, versioned string identifier for this failure.</param>
    /// <param name="message">
    /// Bound by the <see cref="ZeeKayDaConfigurationFailure.Message"/> contract: copied verbatim and
    /// never redacted, so name a caught exception's type, never its message.
    /// </param>
    public void AddFailure(string code, string message) => _failures.Add(new ZeeKayDaConfigurationFailure(code, message));

    /// <summary>Records a structured warning for the runner to log.</summary>
    /// <param name="code">A stable, versioned string identifier for this warning.</param>
    /// <param name="messageTemplate">
    /// An <see cref="ILogger"/> named-placeholder template, passed through unformatted so redaction can act on its fields.
    /// </param>
    /// <param name="level">The <see cref="LogLevel"/> the runner logs this warning at.</param>
    /// <param name="args">The structured arguments matching <paramref name="messageTemplate"/>'s placeholders, in order.</param>
    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args)
        => AddWarningCore(code, messageTemplate, level, args);

    /// <summary>Records a structured warning for the runner to log at <see cref="LogLevel.Warning"/>.</summary>
    /// <param name="code">A stable, versioned string identifier for this warning.</param>
    /// <param name="messageTemplate">
    /// An <see cref="ILogger"/> named-placeholder template, passed through unformatted so redaction can act on its fields.
    /// </param>
    /// <param name="args">The structured arguments matching <paramref name="messageTemplate"/>'s placeholders, in order.</param>
    public void AddWarning(string code, string messageTemplate, params object?[] args)
        => AddWarningCore(code, messageTemplate, LogLevel.Warning, args);

    /// <summary>The failures recorded so far by this invocation.</summary>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> Failures => _failures;

    /// <summary>The warnings recorded so far by this invocation.</summary>
    public IReadOnlyList<StartupVerificationWarning> Warnings => _warnings;

    // Private, so no other call site can pass an arbitrary string off as a messageTemplate.
    private void AddWarningCore(string code, string messageTemplate, LogLevel level, object?[] args)
        => _warnings.Add(new StartupVerificationWarning(code, messageTemplate, level, args));
}
