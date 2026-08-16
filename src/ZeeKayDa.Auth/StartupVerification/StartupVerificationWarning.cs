using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth;

/// <summary>
/// A single structured warning produced by an <see cref="IStartupVerifier"/> or internal startup
/// gate, recorded on a <see cref="StartupVerificationContext"/> via
/// <see cref="StartupVerificationContext.AddWarning(string, string, LogLevel, object?[])"/>.
/// </summary>
/// <param name="Code">A stable, versioned string identifier for this warning.</param>
/// <param name="MessageTemplate">
/// An <see cref="ILogger"/> named-placeholder template (e.g. <c>"{StoreName}"</c>), passed
/// through to the sink unformatted so structured logging backends can index the fields and
/// <c>SecretSanitizingLogger</c> can redact them by key.
/// </param>
/// <param name="Level">The <see cref="LogLevel"/> the runner logs this warning at.</param>
/// <param name="Args">
/// The structured arguments matching <paramref name="MessageTemplate"/>'s placeholders, in order.
/// </param>
public sealed record StartupVerificationWarning(string Code, string MessageTemplate, LogLevel Level, IReadOnlyList<object?> Args);
