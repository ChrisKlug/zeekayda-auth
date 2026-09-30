using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Validates <see cref="AzureKeyVaultRemoteSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddAzureKeyVaultRemoteSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningOptionsValidator : IValidateOptions<AzureKeyVaultRemoteSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultRemoteSigningOptions options)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();

        if (options.KeyIdentifier.VaultUri is null)
        {
            failures.Add(new(
                "configuration.azure_key_vault_remote_signing.key_identifier.missing",
                "AzureKeyVaultRemoteSigningOptions.KeyIdentifier must be set to a valid Key Vault key identifier " +
                "(construct one with 'new KeyVaultKeyIdentifier(keyUri)')."));
        }

        if (options.Credential is null)
        {
            failures.Add(new(
                "configuration.azure_key_vault_remote_signing.credential.missing",
                "AzureKeyVaultRemoteSigningOptions.Credential must be set to a non-null TokenCredential."));
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            failures.Add(new(
                "configuration.azure_key_vault_remote_signing.algorithm.undefined_value",
                $"AzureKeyVaultRemoteSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member."));
        }

        if (options.PreviousVersionsToPublish < 0)
        {
            failures.Add(new(
                "configuration.azure_key_vault_remote_signing.previous_versions_to_publish.negative",
                $"AzureKeyVaultRemoteSigningOptions.PreviousVersionsToPublish ({options.PreviousVersionsToPublish}) " +
                "must be zero or greater. Use 0 to publish no versions older than the signing one."));
        }

        if (options.PreActivationDelay < TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.azure_key_vault_remote_signing.pre_activation_delay.negative",
                $"AzureKeyVaultRemoteSigningOptions.PreActivationDelay ({options.PreActivationDelay}) must be " +
                "zero or greater. Use TimeSpan.Zero to let a newly created key version sign immediately."));
        }

        // This package has no friend access to the core, so the core's ThrowIfAny is out of reach.
        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : throw new ZeeKayDaConfigurationException([.. failures]);
    }
}
