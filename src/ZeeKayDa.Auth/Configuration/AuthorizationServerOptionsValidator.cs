namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates <see cref="AuthorizationServerOptions"/> at startup according to the rules mandated
/// by the OIDC Discovery 1.0 and RFC 8414 specifications.
/// </summary>
/// <remarks>
/// Registered via <c>AddZeeKayDaAuth()</c>, which registers the options with
/// <c>AddZeeKayDaOptions</c>, so that misconfigured servers fail loudly at startup rather than
/// silently at the first request. It is a pure read-only check of the host's values as configured;
/// async checks (e.g. scope presence) are handled by hosted services. The rules themselves live with
/// the options they check — see <c>AuthorizationServerOptionsValidation</c>.
/// </remarks>
internal sealed class AuthorizationServerOptionsValidator : ZeeKayDaOptionsValidator<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? name, AuthorizationServerOptions options) =>
        options.Validate();
}
