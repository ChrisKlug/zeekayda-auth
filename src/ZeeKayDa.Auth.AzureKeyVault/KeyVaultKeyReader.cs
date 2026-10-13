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
        var value = options.Value;
        var credential = value.Credential;
        ArgumentNullException.ThrowIfNull(credential);

        _vaultUri = value.KeyIdentifier.VaultUri;
        _keyName = value.KeyIdentifier.Name;
        _keyClient = new KeyClient(_vaultUri, credential);
    }

    /// <summary>
    /// Test seam: lets unit tests inject a faked <see cref="KeyClient"/>, making the SDK
    /// fault-mapping paths reachable without a live vault.
    /// </summary>
    internal KeyVaultKeyReader(KeyClient keyClient, string keyName, Uri vaultUri)
    {
        _keyClient = keyClient;
        _keyName = keyName;
        _vaultUri = vaultUri;
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<KeyVaultKeyVersionInfo> GetKeyVersionsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var pageable = _keyClient.GetPropertiesOfKeyVersionsAsync(_keyName, cancellationToken);
        await using var enumerator = pageable.GetAsyncEnumerator(cancellationToken);

        var listedAny = false;
        while (true)
        {
            KeyProperties? current;
            try
            {
                if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
                    yield break;

                current = enumerator.Current;
            }
            catch (RequestFailedException ex) when (ex.Status == 404 && !listedAny)
            {
                // A deleted key has no versions to list: deleting it revokes every key it held.
                current = null;
            }
            catch (RequestFailedException ex)
            {
                throw MapRequestFailedException(ex);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw MapUnexpectedFailure(ex);
            }

            if (current is null)
                yield break;

            listedAny = true;
            yield return MapVersion(current, _keyName, _vaultUri);
        }
    }

    /// <summary>
    /// Maps one SDK <see cref="KeyProperties"/> onto <see cref="KeyVaultKeyVersionInfo"/>, failing
    /// closed on a listing entry missing its <c>Enabled</c> or <c>CreatedOn</c> attribute — the two
    /// fields the entire version-selection derivation rests on. A default would be fail-open: an
    /// absent <c>CreatedOn</c> read as ancient satisfies the pre-activation age gate immediately,
    /// and an absent <c>Enabled</c> read as enabled bypasses the revocation lever.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// <paramref name="properties"/> carries no <c>Enabled</c> or no <c>CreatedOn</c> value.
    /// </exception>
    internal static KeyVaultKeyVersionInfo MapVersion(KeyProperties properties, string keyName, Uri vaultUri)
    {
        if (properties.Enabled is not { } enabled || properties.CreatedOn is not { } createdOn)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.incomplete_version_metadata",
                    $"Key Vault returned version '{properties.Version}' of key '{keyName}' in vault " +
                    $"'{vaultUri}' without its Enabled or CreatedOn attribute. Version selection depends " +
                    "on both, so an incomplete listing fails closed rather than guessing."));
        }

        return new KeyVaultKeyVersionInfo(
            properties.Id, properties.Version, enabled, createdOn, properties.NotBefore, properties.ExpiresOn);
    }

    /// <inheritdoc/>
    public async ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(version);

        JsonWebKey key;
        try
        {
            var response = await _keyClient.GetKeyAsync(_keyName, version, cancellationToken).ConfigureAwait(false);
            key = response.Value.Key
                ?? throw new InvalidOperationException("Key Vault returned the version without its key material.");
        }
        catch (RequestFailedException ex)
        {
            throw MapRequestFailedException(ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw MapUnexpectedFailure(ex);
        }

        return MapJsonWebKey(key, version);
    }

    /// <exception cref="ZeeKayDaConfigurationException">
    /// <paramref name="key"/>'s type is unsupported, or its material cannot be imported — a problem
    /// with this one version, never with the vault.
    /// </exception>
    private (AsymmetricAlgorithm, SigningKeyType) MapJsonWebKey(JsonWebKey key, string version)
    {
        var keyType = SigningKeyTypeOf(key.KeyType)
            ?? throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.unsupported_key_type",
                    $"Key Vault key type '{key.KeyType}' is not supported. Only RSA, RSA-HSM, EC, and EC-HSM keys can be used for JWT signing."));

        try
        {
            return keyType == SigningKeyType.Rsa
                ? (key.ToRSA(includePrivateParameters: false), keyType)
                : (key.ToECDsa(includePrivateParameters: false), keyType);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The exception TYPE is named, never ex.Message: it can echo the material it failed to parse.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_key_material",
                    $"Version '{version}' of Key Vault key '{_keyName}' in vault '{_vaultUri}' carries key " +
                    $"material that could not be imported: {ex.GetType().FullName}. See the inner exception " +
                    "for the root cause."),
                ex);
        }
    }

    private static SigningKeyType? SigningKeyTypeOf(KeyType keyType)
    {
        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
            return SigningKeyType.Rsa;

        return keyType == KeyType.Ec || keyType == KeyType.EcHsm ? SigningKeyType.Ec : null;
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
            // The exception TYPE is named, never ex.Message. RequestFailedException.Message carries
            // the response content and headers, and ZeeKayDaConfigurationFailure.Message is a plain
            // string on public API surface that SanitizingLogger cannot redact. The status and
            // ErrorCode above are the safe, operator-actionable parts; the root cause stays available
            // as InnerException.
            _ => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.startup_failure",
                    $"An unexpected error occurred reading Key Vault key '{_keyName}' in vault '{_vaultUri}' " +
                    $"(HTTP {ex.Status}" + (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    $"): {ex.GetType().FullName}. See the inner exception for the root cause."),
                ex),
        };

    // The exception TYPE is named, never ex.Message. An arbitrary underlying provider exception may
    // carry credential material, and ZeeKayDaConfigurationFailure.Message is a plain string on public
    // API surface that SanitizingLogger cannot redact. The root cause stays available to
    // operators as InnerException.
    private ZeeKayDaConfigurationException MapUnexpectedFailure(Exception ex) =>
        new(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.startup_failure",
                $"An unexpected error occurred reading Key Vault key '{_keyName}' in vault '{_vaultUri}': " +
                $"{ex.GetType().FullName}. See the inner exception for the root cause."),
            ex);
}
