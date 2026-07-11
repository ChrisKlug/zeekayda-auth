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
    // KeySourceRefreshInterval doubles as the publish-then-activate delay (ADR 0011 §3.5), just as it does
    // for the remote-signing provider — but here it also gates how often the *private key bytes*
    // of every in-window certificate version are re-downloaded from Key Vault's secret endpoint,
    // which is more sensitive traffic than the remote provider's public-key-only refresh. The same
    // one-minute floor rejects a value so short it would either defeat the publish-then-activate
    // protection against essentially any real-world RP cache TTL, or drive that private-key
    // re-download often enough to risk Key Vault throttling under any real load.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultCachedSigningOptions options)
    {
        var errors = new List<string>();

        if (options.KeySourceRefreshInterval is null)
        {
            errors.Add(
                "AzureKeyVaultCachedSigningOptions.KeySourceRefreshInterval must be a positive, finite TimeSpan. " +
                "null (the local-development provider's 'load once, never reload' static mode) cannot be " +
                "reused here — real Key Vault certificate rotation requires periodic polling on a finite interval.");
        }
        else if (options.KeySourceRefreshInterval.Value < MinimumRefreshInterval)
        {
            errors.Add(
                $"AzureKeyVaultCachedSigningOptions.KeySourceRefreshInterval must be at least {MinimumRefreshInterval} " +
                "(it doubles as the publish-then-activate delay per ADR 0011 §3.5, and a shorter value both " +
                "risks Key Vault throttling and is shorter than most relying parties' JWKS cache TTL). " +
                "You are still responsible for ensuring KeySourceRefreshInterval exceeds your actual relying parties' " +
                "JWKS cache TTL — this floor only rejects values that are almost certainly a mistake.");
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
