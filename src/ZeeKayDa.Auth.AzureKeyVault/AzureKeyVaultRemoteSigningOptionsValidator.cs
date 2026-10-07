using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Validates <see cref="AzureKeyVaultRemoteSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddAzureKeyVaultRemoteSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningOptionsValidator : ZeeKayDaOptionsValidator<AzureKeyVaultRemoteSigningOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(
        string? name,
        AzureKeyVaultRemoteSigningOptions options)
    {
        if (options.KeyIdentifier.VaultUri is null)
        {
            yield return new(
                "configuration.azure_key_vault_remote_signing.key_identifier.missing",
                "AzureKeyVaultRemoteSigningOptions.KeyIdentifier must be set to a valid Key Vault key identifier " +
                "(construct one with 'new KeyVaultKeyIdentifier(keyUri)').");
        }

        if (options.Credential is null)
        {
            yield return new(
                "configuration.azure_key_vault_remote_signing.credential.missing",
                "AzureKeyVaultRemoteSigningOptions.Credential must be set to a non-null TokenCredential.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            yield return new(
                "configuration.azure_key_vault_remote_signing.algorithm.undefined_value",
                $"AzureKeyVaultRemoteSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        if (options.MaxVersions < KeyVaultVersions.MinimumMaxVersions)
        {
            yield return new(
                "configuration.azure_key_vault_remote_signing.max_versions.too_small",
                $"AzureKeyVaultRemoteSigningOptions.MaxVersions is {options.MaxVersions}, but must be at least {KeyVaultVersions.MinimumMaxVersions}: " +
                "a rotation has a staged, a signing and a previous version live at once.");
        }
    }
}
