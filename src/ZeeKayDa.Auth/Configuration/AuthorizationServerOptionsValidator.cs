namespace ZeeKayDa.Auth.Configuration;

/// <summary>Validates <see cref="AuthorizationServerOptions"/> at startup with <c>AuthorizationServerOptionsValidation</c>.</summary>
internal sealed class AuthorizationServerOptionsValidator : ZeeKayDaOptionsValidator<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? name, AuthorizationServerOptions options) =>
        options.Validate();
}
