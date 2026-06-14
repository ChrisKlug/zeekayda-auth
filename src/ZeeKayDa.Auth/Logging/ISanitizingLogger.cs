using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Marker interface for a logger that sanitizes sensitive values before forwarding to the
/// underlying <see cref="ILogger{T}"/>. Registered as an open-generic singleton by
/// <c>AddZeeKayDaAuth()</c> so every ZeeKayDa service automatically receives the sanitizing
/// wrapper without per-class manual construction.
/// </summary>
internal interface ISanitizingLogger<T> : ILogger<T>
{
}
