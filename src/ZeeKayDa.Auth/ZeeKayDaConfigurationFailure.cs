namespace ZeeKayDa.Auth;

/// <summary>
/// A single configuration rule violation within a <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <param name="Code">
/// A stable, versioned string identifier for this violation type (e.g.
/// <c>"client.redirect_uri.fragment"</c>). Codes are part of the public API contract and
/// must not change without a semver-major bump.
/// </param>
/// <param name="Message">
/// A human-readable description of the violation.
/// <para>
/// <strong>Whoever constructs this failure vouches for this text as safe to print.</strong> The
/// framework composes it into <see cref="ZeeKayDaConfigurationException"/>'s own message, and the
/// startup runner copies it verbatim into the exception that aborts <c>StartAsync</c>, where the
/// host's unhandled-exception logger — not a sanitizing one — writes it out. It is a plain string
/// that neither <c>SecretSanitizingLogger</c>'s by-key redaction nor <c>RedactedExceptionWrapper</c>
/// can reach, so nothing removes a secret from it after the fact.
/// </para>
/// <para>
/// In particular, <strong>never interpolate another exception's <see cref="Exception.Message"/>
/// into this text.</strong> An underlying message is untrusted: a storage or vault client's error
/// may embed a connection string or a signed URI. Name the type with
/// <c>ex.GetType().FullName</c> instead and pass the original as the exception's
/// <see cref="Exception.InnerException"/>, which is where a root cause belongs and where the
/// framework's own diagnostics look for it.
/// </para>
/// </param>
public sealed record ZeeKayDaConfigurationFailure(string Code, string Message);
