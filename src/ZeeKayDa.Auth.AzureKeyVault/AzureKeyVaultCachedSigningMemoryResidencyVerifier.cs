using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Records an informational startup notice that this deployment will cache the Azure Key Vault
/// signing certificate's private key in process memory for local signing.
/// </summary>
/// <remarks>
/// Pre-warming and materialize-and-verify of the active signer are handled generically for every
/// provider by the framework-owned <c>SigningStartupSelfTestVerifier</c>; this verifier keeps
/// only the one provider-specific behavior: the memory-residency notice below. It is recorded at
/// <see cref="LogLevel.Information"/>, not a warning level, since caching the private key in
/// process memory is a deliberate architectural choice for this provider, not a misconfiguration
/// — but it must still be visible so operators can see this deployment holds a permanent copy of
/// the signing key.
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningMemoryResidencyVerifier(
    IOptions<AzureKeyVaultCachedSigningOptions> options) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "AzureKeyVaultCachedSigningMemoryResidency";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var certificateIdentifier = options.Value.CertificateIdentifier;
        context.AddWarning(
            "signing.azure_key_vault_cached.memory_resident",
            "ZeeKayDa.Auth: the Azure Key Vault signing certificate '{CertificateName}' in vault " +
            "'{VaultUri}' will have its private key downloaded and cached in process memory for local " +
            "signing (AddAzureKeyVaultCachedSigning). This is a deliberate architectural choice, not a " +
            "misconfiguration — but it means an attacker who achieves process memory read gets a permanent " +
            "copy of the signing key.",
            LogLevel.Information,
            certificateIdentifier.Name, certificateIdentifier.VaultUri);

        return ValueTask.CompletedTask;
    }
}
