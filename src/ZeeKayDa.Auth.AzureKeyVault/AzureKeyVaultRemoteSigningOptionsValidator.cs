using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Validates <see cref="AzureKeyVaultRemoteSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddAzureKeyVaultRemoteSigning()</c> and activated by <c>ValidateOnStart()</c>.
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningOptionsValidator : IValidateOptions<AzureKeyVaultRemoteSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultRemoteSigningOptions options)
    {
        var errors = new List<string>();

        if (options.KeyIdentifier.VaultUri is null)
        {
            errors.Add(
                "AzureKeyVaultRemoteSigningOptions.KeyIdentifier must be set to a valid Key Vault key identifier " +
                "(construct one with 'new KeyVaultKeyIdentifier(keyUri)').");
        }

        if (options.Credential is null)
        {
            errors.Add(
                "AzureKeyVaultRemoteSigningOptions.Credential must be set to a non-null TokenCredential.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"AzureKeyVaultRemoteSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        if (options.PreviousVersionsToPublish < 0)
        {
            errors.Add(
                $"AzureKeyVaultRemoteSigningOptions.PreviousVersionsToPublish ({options.PreviousVersionsToPublish}) " +
                "must be zero or greater. Use 0 to publish no versions older than the signing one.");
        }

        if (options.PreActivationDelay < TimeSpan.Zero)
        {
            errors.Add(
                $"AzureKeyVaultRemoteSigningOptions.PreActivationDelay ({options.PreActivationDelay}) must be " +
                "zero or greater. Use TimeSpan.Zero to let a newly created key version sign immediately.");
        }

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
