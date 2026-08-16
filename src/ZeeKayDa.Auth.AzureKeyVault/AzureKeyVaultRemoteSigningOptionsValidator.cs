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
    // The library cannot enforce that RefreshInterval exceeds a relying party's actual JWKS-cache
    // TTL, but it can reject a value short enough to risk Key Vault throttling under real load.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultRemoteSigningOptions options)
    {
        var errors = new List<string>();

        if (options.RefreshInterval < MinimumRefreshInterval)
        {
            errors.Add(
                $"AzureKeyVaultRemoteSigningOptions.RefreshInterval must be at least {MinimumRefreshInterval} " +
                "(a shorter value both risks Key Vault throttling and is shorter than most relying parties' " +
                "JWKS cache TTL). You are still responsible for ensuring RefreshInterval exceeds your actual " +
                "relying parties' JWKS cache TTL — this floor only rejects values that are almost certainly a " +
                "mistake.");
        }

        // Passes options itself, not options.PublicationLead, so an invalid raw value is turned
        // into a friendly aggregated error here rather than throwing before validation completes.
        if (KeySourcePublicationLeadValidator.ValidateMinimum(
                nameof(AzureKeyVaultRemoteSigningOptions), options) is { } minimumLeadError)
        {
            errors.Add(minimumLeadError);
        }

        if (KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval(
                nameof(AzureKeyVaultRemoteSigningOptions), options) is { } leadVsRefreshError)
        {
            errors.Add(leadVsRefreshError);
        }

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

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
