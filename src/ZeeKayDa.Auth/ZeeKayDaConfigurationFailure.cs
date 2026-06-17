namespace ZeeKayDa.Auth;

/// <summary>
/// A single configuration rule violation within a <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <param name="Code">
/// A stable, versioned string identifier for this violation type (e.g.
/// <c>"client.redirect_uri.fragment"</c>). Codes are part of the public API contract and
/// must not change without a semver-major bump.
/// </param>
/// <param name="Message">A human-readable description of the violation.</param>
public sealed record ZeeKayDaConfigurationFailure(string Code, string Message);
