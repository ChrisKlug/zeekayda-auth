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

        if (options.MaxVersions < KeyVaultVersions.MinimumMaxVersions)
        {
            yield return new(
                "configuration.azure_key_vault_cached_signing.max_versions.too_small",
                $"AzureKeyVaultCachedSigningOptions.MaxVersions is {options.MaxVersions}, but must be at least {KeyVaultVersions.MinimumMaxVersions}: " +
                "a rotation has a staged, a signing and a previous version live at once.");
        }
    }
}
