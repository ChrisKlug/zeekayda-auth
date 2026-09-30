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
        // The validator is only registered by AddClientSecretHasher<T>(), which always adds an entry
        // before the options are ever validated. The 0-hashers case is therefore unreachable here;
        // CompositeClientSecretHasher.ResolveDefault is the runtime guard for that path.
        if (options.Registrations.Count == 1)
            return;

        var defaultCount = options.Registrations.Count(r => r.IsDefault);

        if (defaultCount == 0)
            failures.Add(new(
                "configuration.hashers.no_default",
                "Multiple IClientSecretHasher implementations are registered but none is marked as default. " +
                "Call AddClientSecretHasher<T>(isDefault: true) for exactly one hasher."));

        if (defaultCount > 1)
            failures.Add(new(
                "configuration.hashers.multiple_defaults",
                $"{defaultCount} IClientSecretHasher implementations are marked as default. " +
                "Exactly one hasher must have isDefault: true."));
    }
}
