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
    // KeySourceRefreshInterval doubles as the publish-then-activate delay (ADR 0011 §3.5) — the library
    // cannot know a relying party's actual JWKS-cache TTL, so it cannot enforce the "long enough"
    // half of that requirement, but it CAN reject a value so short it would either defeat the
    // publish-then-activate protection against essentially any real-world RP cache TTL, or drive
    // LoadKeysAsync (a KeyClient list + per-key get call) often enough to risk Key Vault throttling
    // under any real load. This is a floor against near-certain misconfiguration, not a claim that
    // any value above it is automatically safe for a given deployment's RPs.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultRemoteSigningOptions options)
    {
        var errors = new List<string>();

        if (options.KeySourceRefreshInterval is null)
        {
            errors.Add(
                "AzureKeyVaultRemoteSigningOptions.KeySourceRefreshInterval must be a positive, finite TimeSpan. " +
                "null (the local-development provider's 'load once, never reload' static mode) cannot be " +
                "reused here — real Key Vault key rotation requires periodic polling on a finite interval.");
        }
        else if (options.KeySourceRefreshInterval.Value < MinimumRefreshInterval)
        {
            errors.Add(
                $"AzureKeyVaultRemoteSigningOptions.KeySourceRefreshInterval must be at least {MinimumRefreshInterval} " +
                "(it doubles as the publish-then-activate delay per ADR 0011 §3.5, and a shorter value both " +
                "risks Key Vault throttling and is shorter than most relying parties' JWKS cache TTL). " +
                "You are still responsible for ensuring KeySourceRefreshInterval exceeds your actual relying parties' " +
                "JWKS cache TTL — this floor only rejects values that are almost certainly a mistake.");
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
