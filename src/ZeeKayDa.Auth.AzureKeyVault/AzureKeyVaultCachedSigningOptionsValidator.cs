using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Validates <see cref="AzureKeyVaultCachedSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddAzureKeyVaultCachedSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningOptionsValidator : ZeeKayDaOptionsValidator<AzureKeyVaultCachedSigningOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(
        string? name,
        AzureKeyVaultCachedSigningOptions options)
    {
        if (options.CertificateIdentifier.VaultUri is null)
        {
            yield return new(
                "configuration.azure_key_vault_cached_signing.certificate_identifier.missing",
                "AzureKeyVaultCachedSigningOptions.CertificateIdentifier must be set to a valid Key Vault " +
                "certificate identifier (construct one with 'new KeyVaultCertificateIdentifier(certificateUri)').");
        }

        if (options.Credential is null)
        {
            yield return new(
                "configuration.azure_key_vault_cached_signing.credential.missing",
                "AzureKeyVaultCachedSigningOptions.Credential must be set to a non-null TokenCredential.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            yield return new(
                "configuration.azure_key_vault_cached_signing.algorithm.undefined_value",
                $"AzureKeyVaultCachedSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        if (options.PreviousVersionsToPublish < 0)
        {
            yield return new(
                "configuration.azure_key_vault_cached_signing.previous_versions_to_publish.negative",
                $"AzureKeyVaultCachedSigningOptions.PreviousVersionsToPublish ({options.PreviousVersionsToPublish}) " +
                "must be zero or greater. Use 0 to publish no versions older than the signing one.");
        }

        if (options.PreActivationDelay < TimeSpan.Zero)
        {
            yield return new(
                "configuration.azure_key_vault_cached_signing.pre_activation_delay.negative",
                $"AzureKeyVaultCachedSigningOptions.PreActivationDelay ({options.PreActivationDelay}) must be " +
                "zero or greater. Use TimeSpan.Zero to let a newly created certificate version sign immediately.");
        }
    }
}
