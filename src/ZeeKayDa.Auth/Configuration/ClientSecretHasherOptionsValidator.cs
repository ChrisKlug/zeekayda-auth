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
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(
        string? name,
        ClientSecretHasherRegistrationOptions options)
    {
        // None marked is valid: PBKDF2 is then the default.
        var defaultCount = options.Registrations.Count(r => r.IsDefault);

        if (defaultCount > 1)
            yield return new(
                "configuration.hashers.multiple_defaults",
                $"{defaultCount} IClientSecretHasher implementations are marked as default. " +
                "At most one hasher may have isDefault: true; with none, PBKDF2 is the default.");
    }
}
