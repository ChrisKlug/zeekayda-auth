using System.Text;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when ZeeKayDa.Auth is misconfigured. Not recoverable at runtime: fix the configuration and restart.
/// </summary>
/// <remarks>
/// Thrown by the framework's options validators, with a code per failure, and at first use for
/// state only detectable then. An extension point may throw it too: the startup runner keeps each
/// <see cref="ZeeKayDaConfigurationFailure"/>'s code and message, so read the safety contract on
/// <see cref="ZeeKayDaConfigurationFailure.Message"/> first.
/// </remarks>
public class ZeeKayDaConfigurationException : ZeeKayDaException
{
    /// <summary>
    /// Initialises a new instance from one or more structured <paramref name="failures"/>.
    /// </summary>
    /// <param name="failures">The structured failures; must be non-empty.</param>
    public ZeeKayDaConfigurationException(params ZeeKayDaConfigurationFailure[] failures)
        : base(ComposeMessage(failures))
    {
        AggregatedFailures = [.. failures];
    }

    /// <summary>
    /// Initialises a new instance from a single structured <paramref name="failure"/>, preserving
    /// the original exception that triggered it as <see cref="Exception.InnerException"/>.
    /// </summary>
    /// <param name="failure">The structured failure.</param>
    /// <param name="innerException">The lower-level exception that caused the failure.</param>
    public ZeeKayDaConfigurationException(ZeeKayDaConfigurationFailure failure, Exception innerException)
        : base(ComposeMessage([failure]), innerException)
    {
        AggregatedFailures = [failure];
    }

    /// <summary>
    /// Initialises a new instance from several structured <paramref name="failures"/>, preserving an
    /// originating exception as <see cref="Exception.InnerException"/>.
    /// </summary>
    /// <param name="failures">The structured failures; must be non-empty.</param>
    /// <param name="innerException">
    /// The root cause behind one of <paramref name="failures"/>, or an <see cref="AggregateException"/>
    /// over several.
    /// </param>
    public ZeeKayDaConfigurationException(
        IReadOnlyList<ZeeKayDaConfigurationFailure> failures, Exception innerException)
        : base(ComposeMessage([.. NotNull(failures)]), innerException)
    {
        AggregatedFailures = [.. failures];
    }

    /// <summary>
    /// An exception for <paramref name="failures"/> whose inner exception is the one root cause, an
    /// <see cref="AggregateException"/> over several, or absent when there are none.
    /// </summary>
    internal static ZeeKayDaConfigurationException WithRootCauses(
        IReadOnlyList<ZeeKayDaConfigurationFailure> failures, IReadOnlyList<Exception> rootCauses) =>
        rootCauses.Count switch
        {
            0 => new ZeeKayDaConfigurationException([.. failures]),
            1 => new ZeeKayDaConfigurationException(failures, rootCauses[0]),
            _ => new ZeeKayDaConfigurationException(failures, new AggregateException(rootCauses)),
        };

    // Guards inside the base constructor call, where no statement of this constructor can run.
    private static IReadOnlyList<ZeeKayDaConfigurationFailure> NotNull(
        IReadOnlyList<ZeeKayDaConfigurationFailure> failures)
    {
        ArgumentNullException.ThrowIfNull(failures);
        return failures;
    }

    /// <summary>The structured failures behind this exception; never empty.</summary>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> AggregatedFailures { get; }

    /// <summary>Lists every failure's code and message, so a logged startup crash is actionable on its own.</summary>
    private static string ComposeMessage(ZeeKayDaConfigurationFailure[] failures)
    {
        ArgumentNullException.ThrowIfNull(failures);

        if (failures.Length == 0)
            throw new ArgumentException("At least one failure is required.", nameof(failures));

        var builder = new StringBuilder();
        builder.Append(failures.Length).Append(" configuration error(s):");

        foreach (var failure in failures)
        {
            builder.Append("\n  [").Append(failure.Code).Append("] ").Append(failure.Message);
        }

        return builder.ToString();
    }
}
