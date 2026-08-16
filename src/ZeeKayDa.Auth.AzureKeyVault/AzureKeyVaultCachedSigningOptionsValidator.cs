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
    // RefreshInterval gates how often private key bytes are re-downloaded from Key Vault's secret
    // endpoint; this floor rejects a value short enough to risk Key Vault throttling.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultCachedSigningOptions options)
    {
        var errors = new List<string>();

        if (options.RefreshInterval < MinimumRefreshInterval)
        {
            errors.Add(
                $"AzureKeyVaultCachedSigningOptions.RefreshInterval must be at least {MinimumRefreshInterval} " +
                "(a shorter value both risks Key Vault throttling and is shorter than most relying parties' " +
                "JWKS cache TTL). You are still responsible for ensuring RefreshInterval exceeds your actual " +
                "relying parties' JWKS cache TTL — this floor only rejects values that are almost certainly a " +
                "mistake.");
        }

        // Passes options itself, not options.PublicationLead, so an invalid raw value is turned
        // into a friendly aggregated error here rather than throwing before validation completes.
        if (KeySourcePublicationLeadValidator.ValidateMinimum(
                nameof(AzureKeyVaultCachedSigningOptions), options) is { } minimumLeadError)
        {
            errors.Add(minimumLeadError);
        }

        if (KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval(
                nameof(AzureKeyVaultCachedSigningOptions), options) is { } leadVsRefreshError)
        {
            errors.Add(leadVsRefreshError);
        }

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

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
