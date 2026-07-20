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
    // KeyRotationCheckInterval gates how often the *private key bytes* of every in-window
    // certificate version are re-downloaded from Key Vault's secret endpoint, which is more
    // sensitive traffic than the remote provider's public-key-only refresh. The same one-minute
    // floor rejects a value so short it would drive that private-key re-download often enough to
    // risk Key Vault throttling under any real load.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultCachedSigningOptions options)
    {
        var errors = new List<string>();

        if (options.KeyRotationCheckInterval < MinimumRefreshInterval)
        {
            errors.Add(
                $"AzureKeyVaultCachedSigningOptions.KeyRotationCheckInterval must be at least {MinimumRefreshInterval} " +
                "(a shorter value both risks Key Vault throttling and is shorter than most relying parties' " +
                "JWKS cache TTL). You are still responsible for ensuring KeyRotationCheckInterval exceeds your " +
                "actual relying parties' JWKS cache TTL — this floor only rejects values that are almost " +
                "certainly a mistake.");
        }

        if (KeyVaultActivationDelay.ValidateNotShorterThanCheckInterval(
                nameof(AzureKeyVaultCachedSigningOptions),
                options.SigningKeyActivationDelay,
                options.KeyRotationCheckInterval) is { } activationDelayError)
        {
            errors.Add(activationDelayError);
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
