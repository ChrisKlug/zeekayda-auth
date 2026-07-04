using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Azure;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// <see cref="IKeyVaultKeyReader"/> implementation backed by a real
/// <see cref="Azure.Security.KeyVault.Keys.KeyClient"/>.
/// </summary>
/// <remarks>
/// Every <see cref="Azure.RequestFailedException"/> and other transport fault raised by the
/// underlying SDK is mapped here to a <see cref="ZeeKayDaConfigurationException"/> carrying a
/// stable failure code and enough context (vault, key name, HTTP status, SDK error code) to be
/// actionable, without ever including key material.
/// </remarks>
internal sealed class KeyVaultKeyReader : IKeyVaultKeyReader
{
    private readonly KeyClient _keyClient;
    private readonly string _keyName;
    private readonly Uri _vaultUri;

    public KeyVaultKeyReader(IOptions<AzureKeyVaultRemoteSigningOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var value = options.Value;
        var credential = value.Credential;
        ArgumentNullException.ThrowIfNull(credential);

        _vaultUri = value.KeyIdentifier.VaultUri;
        _keyName = value.KeyIdentifier.Name;
        _keyClient = new KeyClient(_vaultUri, credential);
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<KeyVaultKeyVersionInfo> GetKeyVersionsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var pageable = _keyClient.GetPropertiesOfKeyVersionsAsync(_keyName, cancellationToken);
        await using var enumerator = pageable.GetAsyncEnumerator(cancellationToken);

        while (true)
        {
            KeyProperties current;
            try
            {
                if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
                    yield break;

                current = enumerator.Current;
            }
            catch (RequestFailedException ex)
            {
                throw MapRequestFailedException(ex);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw MapUnexpectedFailure(ex);
            }

            yield return new KeyVaultKeyVersionInfo(
                current.Id,
                current.Version,
                current.Enabled ?? true,
                current.CreatedOn ?? DateTimeOffset.MinValue,
                current.NotBefore,
                current.ExpiresOn);
        }
    }

    /// <inheritdoc/>
    public async ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(version);

        try
        {
            var response = await _keyClient.GetKeyAsync(_keyName, version, cancellationToken).ConfigureAwait(false);
            return MapJsonWebKey(response.Value.Key);
        }
        catch (RequestFailedException ex)
        {
            throw MapRequestFailedException(ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw MapUnexpectedFailure(ex);
        }
    }

    private static (AsymmetricAlgorithm, SigningKeyType) MapJsonWebKey(JsonWebKey key)
    {
        if (key.KeyType == KeyType.Rsa || key.KeyType == KeyType.RsaHsm)
            return (key.ToRSA(includePrivateParameters: false), SigningKeyType.Rsa);

        if (key.KeyType == KeyType.Ec || key.KeyType == KeyType.EcHsm)
            return (key.ToECDsa(includePrivateParameters: false), SigningKeyType.Ec);

        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.unsupported_key_type",
                $"Key Vault key type '{key.KeyType}' is not supported. Only RSA, RSA-HSM, EC, and EC-HSM keys can be used for JWT signing."));
    }

    private ZeeKayDaConfigurationException MapRequestFailedException(RequestFailedException ex) =>
        ex.Status switch
        {
            404 => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.key_not_found",
                    $"Key Vault key '{_keyName}' was not found in vault '{_vaultUri}' (HTTP 404" +
                    (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    "). Verify the key name and vault URI, and that the key has not been deleted or purged.")),
            401 or 403 => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.access_denied",
                    $"Access to Key Vault key '{_keyName}' in vault '{_vaultUri}' was denied (HTTP {ex.Status}" +
                    (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    "). Verify the configured credential has 'Key Vault Crypto User' (or an access-policy grant " +
                    "of 'get' and 'sign' key permissions) on this vault.")),
            _ => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.startup_failure",
                    $"An unexpected error occurred reading Key Vault key '{_keyName}' in vault '{_vaultUri}' " +
                    $"(HTTP {ex.Status}" + (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    $"): {ex.Message}")),
        };

    private ZeeKayDaConfigurationException MapUnexpectedFailure(Exception ex) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.azure_key_vault.startup_failure",
            $"An unexpected error occurred reading Key Vault key '{_keyName}' in vault '{_vaultUri}': {ex.Message}"));
}
