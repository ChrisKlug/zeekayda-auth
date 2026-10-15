using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Reads certificate versions through the Key Vault SDK. The private key comes from the linked secret's
/// PFX, parsed with <see cref="Pkcs12Info"/> so it is never written to an OS key store.
/// </summary>
internal sealed class KeyVaultCertificateReader : IKeyVaultCertificateReader
{
    // Key Vault's default for a managed certificate's secret; a PEM secret is refused.
    private const string Pkcs12ContentType = "application/x-pkcs12";

    private readonly CertificateClient _certificateClient;
    private readonly SecretClient _secretClient;
    private readonly string _certificateName;
    private readonly Uri _vaultUri;
    private readonly Func<RSA> _createRsa;
    private readonly Func<ECDsa> _createEcdsa;

    public KeyVaultCertificateReader(IOptions<AzureKeyVaultCachedSigningOptions> options)
    {
        var value = options.Value;
        var credential = value.Credential;
        ArgumentNullException.ThrowIfNull(credential);

        _vaultUri = value.CertificateIdentifier.VaultUri;
        _certificateName = value.CertificateIdentifier.Name;
        _certificateClient = new CertificateClient(_vaultUri, credential);
        _secretClient = new SecretClient(_vaultUri, credential);
        _createRsa = RSA.Create;
        _createEcdsa = ECDsa.Create;
    }

    /// <summary>Test seam: faked SDK clients and key factories.</summary>
    internal KeyVaultCertificateReader(
        CertificateClient certificateClient, SecretClient secretClient, KeyVaultCertificateIdentifier identifier,
        Func<RSA>? createRsa = null, Func<ECDsa>? createEcdsa = null)
    {
        _certificateClient = certificateClient;
        _secretClient = secretClient;
        _certificateName = identifier.Name;
        _vaultUri = identifier.VaultUri;
        _createRsa = createRsa ?? RSA.Create;
        _createEcdsa = createEcdsa ?? ECDsa.Create;
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<KeyVaultCertificateVersionInfo> GetCertificateVersionsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var pageable = _certificateClient.GetPropertiesOfCertificateVersionsAsync(_certificateName, cancellationToken);
        await using var enumerator = pageable.GetAsyncEnumerator(cancellationToken);

        var listedAny = false;
        while (true)
        {
            CertificateProperties? current;
            try
            {
                if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
                    yield break;

                current = enumerator.Current;
            }
            catch (RequestFailedException ex) when (ex.Status == 404 && !listedAny)
            {
                // A deleted certificate has no versions to list: deleting it revokes every key it held.
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
            yield return MapVersion(current, _certificateName, _vaultUri);
        }
    }

    /// <summary>
    /// Maps one listing entry, failing closed when <c>Enabled</c> or <c>CreatedOn</c> is missing: any
    /// default for either would let a version sign early or survive being disabled.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// <paramref name="properties"/> carries no <c>Enabled</c> or no <c>CreatedOn</c> value.
    /// </exception>
    internal static KeyVaultCertificateVersionInfo MapVersion(
        CertificateProperties properties, string certificateName, Uri vaultUri)
    {
        if (properties.Enabled is not { } enabled || properties.CreatedOn is not { } createdOn)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.incomplete_version_metadata",
                    $"Key Vault returned version '{properties.Version}' of certificate '{certificateName}' in " +
                    $"vault '{vaultUri}' without its Enabled or CreatedOn attribute. Version selection depends " +
                    "on both, so an incomplete listing fails closed rather than guessing."));
        }

        return new KeyVaultCertificateVersionInfo(
            properties.Id, properties.Version, enabled, createdOn, properties.NotBefore, properties.ExpiresOn);
    }

    /// <inheritdoc/>
    public async ValueTask<(AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType)> GetPrivateKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(version);

        var secret = await DownloadCertificateSecretAsync(version, cancellationToken).ConfigureAwait(false);
        return ExtractPrivateKey(secret, version);
    }

    /// <inheritdoc/>
    public async ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetPublicKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(version);

        // The Cer needs no secrets/get and no PFX download.
        var certificate = await GetCertificateVersionAsync(version, cancellationToken).ConfigureAwait(false);
        return ExtractPublicKey(certificate.Cer, version);
    }

    private async ValueTask<KeyVaultCertificate> GetCertificateVersionAsync(
        string version, CancellationToken cancellationToken)
    {
        try
        {
            var certificate = await _certificateClient
                .GetCertificateVersionAsync(_certificateName, version, cancellationToken)
                .ConfigureAwait(false);
            return certificate.Value;
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

    private async ValueTask<KeyVaultSecret> DownloadCertificateSecretAsync(string version, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateVersionAsync(version, cancellationToken).ConfigureAwait(false);

        if (!TryGetSecretIdentifier(certificate, out var secretIdentifier))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.certificate_missing_secret",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' " +
                    "has no linked secret identifier and cannot be used for local signing."));
        }

        try
        {
            var secret = await _secretClient
                .GetSecretAsync(secretIdentifier.Name, secretIdentifier.Version, cancellationToken)
                .ConfigureAwait(false);
            return secret.Value;
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

    /// <summary>The linked secret identifier; <see cref="KeyVaultCertificate.SecretId"/> throws when there is none.</summary>
    private static bool TryGetSecretIdentifier(
        KeyVaultCertificate certificate, out KeyVaultSecretIdentifier secretIdentifier)
    {
        Uri? secretId;
        try
        {
            secretId = certificate.SecretId;
        }
        catch (ArgumentException)
        {
            secretId = null;
        }

        if (secretId is null)
        {
            secretIdentifier = default;
            return false;
        }

        return KeyVaultSecretIdentifier.TryCreate(secretId, out secretIdentifier);
    }

    /// <summary>Extracts the public key from the version's Cer, never its secret.</summary>
    private (AsymmetricAlgorithm, SigningKeyType) ExtractPublicKey(byte[] cerBytes, string version)
    {
        using var certificate = LoadCertificate(cerBytes, version);

        try
        {
            var rsaPublicKey = certificate.GetRSAPublicKey();
            if (rsaPublicKey is not null)
                return (rsaPublicKey, SigningKeyType.Rsa);

            var ecdsaPublicKey = certificate.GetECDsaPublicKey();
            if (ecdsaPublicKey is not null)
                return (ecdsaPublicKey, SigningKeyType.Ec);

            throw UnsupportedKeyTypeException(version);
        }
        catch (ZeeKayDaConfigurationException)
        {
            // Keeps its own code rather than being reclassified below.
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A loaded certificate's key accessor can still throw on an unreadable key algorithm.
            throw new KeyVaultVersionMaterialException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_certificate_public_key",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' " +
                    $"carries a public key that could not be read: {ex.GetType().FullName}. See the inner " +
                    "exception for the root cause."),
                ex);
        }
    }

    private X509Certificate2 LoadCertificate(byte[] cerBytes, string version)
    {
        try
        {
            return X509CertificateLoader.LoadCertificate(cerBytes);
        }
        catch (CryptographicException ex)
        {
            // Never ex.Message: a failure message is not redacted, so the cause travels as the inner exception.
            throw new KeyVaultVersionMaterialException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_certificate_public_key",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' did " +
                    $"not contain a valid public certificate (Cer): {ex.GetType().FullName}. See the inner " +
                    "exception for the root cause."),
                ex);
        }
    }

    private (AsymmetricAlgorithm, SigningKeyType) ExtractPrivateKey(KeyVaultSecret secret, string version)
    {
        var contentType = secret.Properties.ContentType;
        if (contentType is not null && !string.Equals(contentType, Pkcs12ContentType, StringComparison.OrdinalIgnoreCase))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.unsupported_certificate_content_type",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' has " +
                    $"secret content type '{contentType}'. AddAzureKeyVaultCachedSigning only supports PKCS#12 " +
                    $"('{Pkcs12ContentType}') certificates."));
        }

        if (string.IsNullOrEmpty(secret.Value))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_certificate_secret",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' did " +
                    "not contain a valid base64-encoded PKCS#12 payload."));
        }

        byte[] pfxBytes;
        try
        {
            pfxBytes = Convert.FromBase64String(secret.Value);
        }
        catch (FormatException)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_certificate_secret",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' did " +
                    "not contain a valid base64-encoded PKCS#12 payload."));
        }

        try
        {
            return ExtractPrivateKeyFromPkcs12(pfxBytes, version);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
        {
            // Never ex.Message: a failure message is not redacted, so the cause travels as the inner exception.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_certificate_secret",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' could " +
                    $"not be parsed as a PKCS#12 certificate: {ex.GetType().FullName}. See the inner exception " +
                    "for the root cause."),
                ex);
        }
    }

    /// <summary>
    /// Parses a PKCS#12 payload purely in managed memory and imports the first private key bag
    /// found into an <see cref="RSA"/> or <see cref="ECDsa"/> instance.
    /// </summary>
    private (AsymmetricAlgorithm, SigningKeyType) ExtractPrivateKeyFromPkcs12(byte[] pfxBytes, string version)
    {
        var pkcs12 = Pkcs12Info.Decode(pfxBytes, out _, skipCopy: true);

        foreach (var safeContents in pkcs12.AuthenticatedSafe)
        {
            // A Key Vault-exported PFX has an empty password.
            if (safeContents.ConfidentialityMode == Pkcs12ConfidentialityMode.Password)
                safeContents.Decrypt(ReadOnlySpan<char>.Empty);

            foreach (var bag in safeContents.GetBags())
            {
                if (bag is Pkcs12KeyBag or Pkcs12ShroudedKeyBag)
                    return ImportPrivateKey(bag, version);
            }
        }

        // A non-exportable certificate's secret is still a 200 with a PFX; the missing key bag is the only signal.
        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.certificate_not_exportable",
                $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' " +
                "was created with a non-exportable key policy, so Key Vault did not include a private " +
                "key in the downloaded certificate. AddAzureKeyVaultCachedSigning requires an exportable " +
                "certificate policy. Use AddAzureKeyVaultRemoteSigning instead if the private key must " +
                "never leave Key Vault."));
    }

    private (AsymmetricAlgorithm, SigningKeyType) ImportPrivateKey(Pkcs12SafeBag keyBag, string version) =>
        Pkcs12PrivateKey.Import(keyBag, ReadOnlySpan<char>.Empty, _createRsa, _createEcdsa) switch
        {
            RSA rsa => (rsa, SigningKeyType.Rsa),
            ECDsa ecdsa => (ecdsa, SigningKeyType.Ec),
            _ => throw UnsupportedKeyTypeException(version),
        };

    private KeyVaultVersionMaterialException UnsupportedKeyTypeException(string version) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.azure_key_vault.unsupported_key_type",
            $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' does not " +
            "carry an RSA or EC private key. Only RSA and EC certificate keys are supported for JWT signing."));

    private ZeeKayDaConfigurationException MapRequestFailedException(RequestFailedException ex) =>
        ex.Status switch
        {
            404 => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.certificate_not_found",
                    $"Key Vault certificate '{_certificateName}' was not found in vault '{_vaultUri}' (HTTP 404" +
                    (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    "). Verify the certificate name and vault URI, and that the certificate has not been deleted " +
                    "or purged.")),
            401 or 403 => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.access_denied",
                    $"Access to Key Vault certificate '{_certificateName}' in vault '{_vaultUri}' was denied " +
                    $"(HTTP {ex.Status}" + (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    "). Verify the configured credential has been granted the required permissions (via an " +
                    "access policy, or the 'Key Vault Certificate User' built-in RBAC role) on this vault: " +
                    "every included version requires 'certificates/get', and the active signing version " +
                    "additionally requires 'secrets/get' to download its private key.")),
            // Never ex.Message: it carries the response content and headers.
            _ => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.startup_failure",
                    $"An unexpected error occurred reading Key Vault certificate '{_certificateName}' in vault " +
                    $"'{_vaultUri}' (HTTP {ex.Status}" + (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    $"): {ex.GetType().FullName}. See the inner exception for the root cause."),
                ex),
        };

    // Never ex.Message: a provider exception may carry credential material.
    private ZeeKayDaConfigurationException MapUnexpectedFailure(Exception ex) =>
        new(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.startup_failure",
                $"An unexpected error occurred reading Key Vault certificate '{_certificateName}' in vault " +
                $"'{_vaultUri}': {ex.GetType().FullName}. See the inner exception for the root cause."),
            ex);
}
