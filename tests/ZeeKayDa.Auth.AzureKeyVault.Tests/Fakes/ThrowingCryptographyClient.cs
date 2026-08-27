using Azure.Security.KeyVault.Keys.Cryptography;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// A <see cref="CryptographyClient"/> built on the SDK's protected mocking constructor whose
/// sign call always throws, so <see cref="KeyVaultSigner"/>'s fault-mapping paths (throttling,
/// generic request failures) can be exercised without a live vault. Happy-path tests use the
/// SDK's own local-cryptography client (<c>new CryptographyClient(JsonWebKey)</c>) instead.
/// </summary>
internal sealed class ThrowingCryptographyClient(Exception exception) : CryptographyClient
{
    public override Task<SignResult> SignDataAsync(
        SignatureAlgorithm algorithm, byte[] data, CancellationToken cancellationToken = default) =>
        throw exception;
}
