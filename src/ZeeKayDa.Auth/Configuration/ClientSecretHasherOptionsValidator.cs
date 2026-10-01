using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates <see cref="ClientSecretHasherRegistrationOptions"/> at startup to catch
/// hasher misconfiguration before the host accepts requests.
/// </summary>
internal sealed class ClientSecretHasherOptionsValidator
    : ZeeKayDaOptionsValidator<ClientSecretHasherRegistrationOptions>
{
    /// <inheritdoc/>
    protected override void Validate(
        string? name,
        ClientSecretHasherRegistrationOptions options,
        ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        // None marked is valid: PBKDF2 is then the default.
        var defaultCount = options.Registrations.Count(r => r.IsDefault);

        if (defaultCount > 1)
            failures.Add(new(
                "configuration.hashers.multiple_defaults",
                $"{defaultCount} IClientSecretHasher implementations are marked as default. " +
                "Exactly one hasher must have isDefault: true."));
    }
}
