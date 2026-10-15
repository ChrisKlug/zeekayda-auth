namespace ZeeKayDa.Auth;

/// <summary>
/// A single configuration rule violation within a <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <param name="Code">
/// A stable identifier for the violation, such as <c>"client.redirect_uri.fragment"</c>; part of the public API.
/// </param>
/// <param name="Message">
/// A human-readable description of the violation.
/// <para>
/// <strong>Whoever constructs this failure vouches for this text as safe to print.</strong> It
/// reaches unsanitized startup logs, critical log entries and, in development, error pages, and no
/// redaction can reach it. Never interpolate another exception's <see cref="Exception.Message"/>:
/// name its type with <c>ex.GetType().FullName</c> and pass it as the inner exception.
/// </para>
/// </param>
public sealed record ZeeKayDaConfigurationFailure(string Code, string Message);
