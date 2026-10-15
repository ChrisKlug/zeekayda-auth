using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>A structured warning a startup check recorded on its <see cref="StartupVerificationContext"/>.</summary>
/// <param name="Code">A stable, versioned string identifier for this warning.</param>
/// <param name="MessageTemplate">
/// An <see cref="ILogger"/> named-placeholder template, passed through unformatted so redaction can act on its fields.
/// </param>
/// <param name="Level">The <see cref="LogLevel"/> the runner logs this warning at.</param>
/// <param name="Args">
/// The structured arguments matching <paramref name="MessageTemplate"/>'s placeholders, in order.
/// </param>
public sealed record StartupVerificationWarning(string Code, string MessageTemplate, LogLevel Level, IReadOnlyList<object?> Args);
