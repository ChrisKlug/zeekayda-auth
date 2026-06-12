using System.Text;

namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when the ZeeKayDa.Auth framework is misconfigured or when a required configuration
/// value is absent or invalid at the point where it is first needed.
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates a setup-time error in the host application — missing service
/// registrations, invalid options values, or configuration state that is required for the
/// framework to operate but was not provided. It is not recoverable at runtime; the correct
/// response is to fix the configuration and restart.
/// </para>
/// <para>
/// Most configuration errors are caught earlier by the startup validator
/// (<c>ValidateOnStart()</c> / <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/>).
/// This exception covers the residual cases where invalid state is only detectable at the moment
/// the framework needs to use a value — for example, when <c>MapZeeKayDaAuth()</c> is called
/// before <c>AddZeeKayDaAuth()</c>.
/// </para>
/// </remarks>
public class ZeeKayDaConfigurationException : ZeeKayDaException
{
    /// <summary>
    /// Initialises a new instance from one or more structured <paramref name="failures"/>.
    /// </summary>
    /// <param name="failures">
    /// The structured failures. Must be non-empty; each entry carries a stable
    /// <see cref="ZeeKayDaConfigurationFailure.Code"/> and a human-readable message.
    /// </param>
    public ZeeKayDaConfigurationException(params ZeeKayDaConfigurationFailure[] failures)
        : base(ComposeMessage(failures))
    {
        AggregatedFailures = [.. failures];
    }

    /// <summary>
    /// The structured validation failures that contributed to this exception.
    /// Always contains at least one entry.
    /// </summary>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> AggregatedFailures { get; }

    /// <summary>
    /// Composes a human-readable message that lists every failure's code and description, so that
    /// <see cref="Exception.ToString"/> (what console and most log sinks print at a startup crash)
    /// is actionable on its own without inspecting <see cref="AggregatedFailures"/>.
    /// </summary>
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
