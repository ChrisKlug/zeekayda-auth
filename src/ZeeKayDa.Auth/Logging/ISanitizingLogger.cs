using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Marker interface for a logger that sanitizes sensitive values before forwarding to the
/// underlying <see cref="ILogger{T}"/>. Registered as an open-generic singleton by
/// <c>AddZeeKayDaAuth()</c> so every ZeeKayDa service automatically receives the sanitizing
/// wrapper without per-class manual construction.
/// </summary>
/// <remarks>
/// <para>
/// This interface exists so that first- and third-party services alike — including packages
/// such as <c>ZeeKayDa.Auth.AzureKeyVault</c> that reference only core <c>ZeeKayDa.Auth</c>, not
/// <c>ZeeKayDa.Auth.AspNetCore</c> — can constructor-inject the framework's sanitizing logger
/// without requiring <c>InternalsVisibleTo</c>, which can only ever name first-party assemblies
/// at build time. This mirrors why <see cref="ZeeKayDa.Auth.Tokens.JwkThumbprint"/> is public
/// (see ADR 0011 Amendment 2(c)/(d)).
/// </para>
/// <para>
/// <strong>Do not implement this interface directly.</strong> Obtain an instance only via
/// constructor injection. The framework registers exactly one implementation
/// (<c>SecretSanitizingLogger&lt;T&gt;</c>, which stays internal) via
/// <c>TryAddSingleton(typeof(ISanitizingLogger&lt;&gt;), typeof(SecretSanitizingLogger&lt;&gt;))</c>.
/// A host that registers its own <c>ISanitizingLogger&lt;&gt;</c> implementation before calling
/// <c>AddZeeKayDaAuth()</c> shadows the framework's redaction wrapper for every ZeeKayDa service,
/// silently disabling the credential-redaction guarantee described in ADR 0007 §7. A hosted
/// startup validator detects this and fails fast — see
/// <c>SanitizingLoggerRegistrationStartupValidator</c> in <c>ZeeKayDa.Auth.AspNetCore</c>.
/// </para>
/// </remarks>
public interface ISanitizingLogger<T> : ILogger<T>
{
}
