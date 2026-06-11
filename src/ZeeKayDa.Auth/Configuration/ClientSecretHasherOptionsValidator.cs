using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates <see cref="ClientSecretHasherRegistrationOptions"/> at startup to catch
/// hasher misconfiguration before the host accepts requests.
/// </summary>
internal sealed class ClientSecretHasherOptionsValidator
    : IValidateOptions<ClientSecretHasherRegistrationOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, ClientSecretHasherRegistrationOptions options)
    {
        // The validator is only registered by AddSecretsHasher<T>(), which always adds an entry
        // before ValidateOnStart() runs. The 0-hashers case is therefore unreachable here;
        // CompositeClientSecretHasher.ResolveDefault is the runtime guard for that path.
        if (options.Registrations.Count == 1)
            return ValidateOptionsResult.Success;

        var defaultCount = options.Registrations.Count(r => r.IsDefault);

        if (defaultCount == 0)
            return ValidateOptionsResult.Fail(
                "Multiple IClientSecretHasher implementations are registered but none is marked as default. " +
                "Call AddSecretsHasher<T>(isDefault: true) for exactly one hasher.");

        if (defaultCount > 1)
            return ValidateOptionsResult.Fail(
                $"{defaultCount} IClientSecretHasher implementations are marked as default. " +
                "Exactly one hasher must have isDefault: true.");

        return ValidateOptionsResult.Success;
    }
}
