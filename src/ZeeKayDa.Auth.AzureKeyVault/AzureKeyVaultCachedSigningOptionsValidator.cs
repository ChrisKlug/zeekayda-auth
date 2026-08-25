using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Validates <see cref="AzureKeyVaultCachedSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddAzureKeyVaultCachedSigning()</c> and activated by <c>ValidateOnStart()</c>.
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningOptionsValidator : IValidateOptions<AzureKeyVaultCachedSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultCachedSigningOptions options)
    {
        var errors = new List<string>();

        if (options.CertificateIdentifier.VaultUri is null)
        {
            errors.Add(
                "AzureKeyVaultCachedSigningOptions.CertificateIdentifier must be set to a valid Key Vault " +
                "certificate identifier (construct one with 'new KeyVaultCertificateIdentifier(certificateUri)').");
        }

        if (options.Credential is null)
        {
            errors.Add(
                "AzureKeyVaultCachedSigningOptions.Credential must be set to a non-null TokenCredential.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"AzureKeyVaultCachedSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        if (options.PreviousVersionsToPublish < 0)
        {
            errors.Add(
                $"AzureKeyVaultCachedSigningOptions.PreviousVersionsToPublish ({options.PreviousVersionsToPublish}) " +
                "must be zero or greater. Use 0 to publish no versions older than the signing one.");
        }

        if (options.PreActivationDelay < TimeSpan.Zero)
        {
            errors.Add(
                $"AzureKeyVaultCachedSigningOptions.PreActivationDelay ({options.PreActivationDelay}) must be " +
                "zero or greater. Use TimeSpan.Zero to let a newly created certificate version sign immediately.");
        }

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
