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
/// <see cref="IKeyVaultCertificateReader"/> implementation backed by real
/// <see cref="Azure.Security.KeyVault.Certificates.CertificateClient"/> and
/// <see cref="Azure.Security.KeyVault.Secrets.SecretClient"/> instances.
/// </summary>
/// <remarks>
/// True private key export requires downloading the certificate's linked secret, since
/// <c>KeyClient.GetKeyAsync</c> never returns private key material regardless of a key's
/// exportable flag; the secret's value contains the full PFX only when the key policy is
/// exportable. Every transport fault from the SDK is mapped to a
/// <see cref="ZeeKayDaConfigurationException"/> carrying a stable failure code and enough context
/// to be actionable, without ever including key material.
/// <para>
/// The downloaded PFX is parsed with <see cref="Pkcs12Info"/>, a pure managed ASN.1/PKCS#12
/// parser, rather than <c>X509CertificateLoader.LoadPkcs12</c> — the latter always constructs an
/// OS-backed <c>X509Certificate2</c>, and on macOS that requires writing the private key to a
/// transient keychain on disk. Parsing directly and importing the key bag into an
/// <see cref="RSA"/>/<see cref="ECDsa"/> instance keeps the private key in managed memory only.
/// </para>
/// </remarks>
internal sealed class KeyVaultCertificateReader : IKeyVaultCertificateReader
{
    // Key Vault's default content type for a managed certificate's secret value. PEM-formatted
    // secrets are out of scope here; such a certificate fails fast below instead.
    private const string Pkcs12ContentType = "application/x-pkcs12";

    private readonly CertificateClient _certificateClient;
    private readonly SecretClient _secretClient;
    private readonly string _certificateName;
    private readonly Uri _vaultUri;
    private readonly Func<RSA> _createRsa;
    private readonly Func<ECDsa> _createEcdsa;

    public KeyVaultCertificateReader(IOptions<AzureKeyVaultCachedSigningOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
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

    /// <summary>
    /// Test seam: lets unit tests inject faked <see cref="CertificateClient"/>/<see cref="SecretClient"/>
    /// instances, making the SDK fault-mapping paths reachable without a live vault, and faked
    /// <see cref="RSA"/>/<see cref="ECDsa"/> factories, making the private-key import failure arms
    /// observable — a handle that fails to import is created and disposed entirely inside this class.
    /// </summary>
    internal KeyVaultCertificateReader(
        CertificateClient certificateClient, SecretClient secretClient, string certificateName, Uri vaultUri,
        Func<RSA>? createRsa = null, Func<ECDsa>? createEcdsa = null)
    {
        _certificateClient = certificateClient;
        _secretClient = secretClient;
        _certificateName = certificateName;
        _vaultUri = vaultUri;
        _createRsa = createRsa ?? RSA.Create;
        _createEcdsa = createEcdsa ?? ECDsa.Create;
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<KeyVaultCertificateVersionInfo> GetCertificateVersionsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var pageable = _certificateClient.GetPropertiesOfCertificateVersionsAsync(_certificateName, cancellationToken);
        await using var enumerator = pageable.GetAsyncEnumerator(cancellationToken);

        while (true)
        {
            CertificateProperties current;
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

            yield return MapVersion(current, _certificateName, _vaultUri);
        }
    }

    /// <summary>
    /// Maps one SDK <see cref="CertificateProperties"/> onto
    /// <see cref="KeyVaultCertificateVersionInfo"/>, failing closed on a listing entry missing its
    /// <c>Enabled</c> or <c>CreatedOn</c> attribute — the two fields the entire version-selection
    /// derivation rests on. A default would be fail-open: an absent <c>CreatedOn</c> read as
    /// ancient satisfies the pre-activation age gate immediately, and an absent <c>Enabled</c> read
    /// as enabled bypasses the revocation lever.
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

        // Deliberately does not touch _secretClient: CertificateClient's response already carries
        // the public certificate (Cer) without requiring secrets/get or downloading the PFX.
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

    /// <summary>
    /// Reads the certificate's linked secret identifier without letting an absent sid escape as a
    /// raw SDK exception: <see cref="KeyVaultCertificate.SecretId"/> parses the sid on every read
    /// and throws when the certificate carries none at all. A missing sid and an unusable one are
    /// the same operator-facing condition, so both fail closed through the caller's guard.
    /// </summary>
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

    /// <summary>
    /// Extracts the public key from a certificate version's CER-formatted public certificate,
    /// never the linked secret/PFX, so this never requires <c>secrets/get</c>.
    /// </summary>
    private (AsymmetricAlgorithm, SigningKeyType) ExtractPublicKey(byte[] cerBytes, string version)
    {
        using var certificate = LoadCertificate(cerBytes, version);

        var rsaPublicKey = certificate.GetRSAPublicKey();
        if (rsaPublicKey is not null)
            return (rsaPublicKey, SigningKeyType.Rsa);

        var ecdsaPublicKey = certificate.GetECDsaPublicKey();
        if (ecdsaPublicKey is not null)
            return (ecdsaPublicKey, SigningKeyType.Ec);

        throw UnsupportedKeyTypeException(version);
    }

    private X509Certificate2 LoadCertificate(byte[] cerBytes, string version)
    {
        try
        {
            return X509CertificateLoader.LoadCertificate(cerBytes);
        }
        catch (CryptographicException ex)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_certificate_public_key",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' did " +
                    $"not contain a valid public certificate (Cer): {ex.Message}"));
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
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.invalid_certificate_secret",
                    $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' could " +
                    $"not be parsed as a PKCS#12 certificate: {ex.Message}"));
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
            // A Key Vault-exported PFX has no real password; Decrypt(ReadOnlySpan<char>.Empty) is
            // the "no password" case here.
            if (safeContents.ConfidentialityMode == Pkcs12ConfidentialityMode.Password)
                safeContents.Decrypt(ReadOnlySpan<char>.Empty);

            foreach (var bag in safeContents.GetBags())
            {
                switch (bag)
                {
                    case Pkcs12KeyBag keyBag:
                        return ImportPrivateKey(keyBag.Pkcs8PrivateKey.Span, version);
                    case Pkcs12ShroudedKeyBag shroudedKeyBag:
                        return ImportShroudedPrivateKey(shroudedKeyBag.EncryptedPkcs8PrivateKey.Span, version);
                }
            }
        }

        // When a certificate's key policy is non-exportable, Key Vault's secret endpoint still
        // returns HTTP 200 with a PKCS#12 payload that simply omits the private key bag — "no key
        // bag was found" is the only reliable signal for this case.
        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.certificate_not_exportable",
                $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' " +
                "was created with a non-exportable key policy, so Key Vault did not include a private " +
                "key in the downloaded certificate. AddAzureKeyVaultCachedSigning requires an exportable " +
                "certificate policy. Use AddAzureKeyVaultRemoteSigning instead if the private key must " +
                "never leave Key Vault."));
    }

    private (AsymmetricAlgorithm, SigningKeyType) ImportPrivateKey(ReadOnlySpan<byte> pkcs8PrivateKey, string version)
    {
        var rsa = _createRsa();
        try
        {
            rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
            return (rsa, SigningKeyType.Rsa);
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
        }
        catch
        {
            // This handle must never leak regardless of what gets thrown.
            rsa.Dispose();
            throw;
        }

        var ecdsa = _createEcdsa();
        try
        {
            ecdsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
            return (ecdsa, SigningKeyType.Ec);
        }
        catch (CryptographicException)
        {
            ecdsa.Dispose();
            throw UnsupportedKeyTypeException(version);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    private (AsymmetricAlgorithm, SigningKeyType) ImportShroudedPrivateKey(
        ReadOnlySpan<byte> encryptedPkcs8PrivateKey, string version)
    {
        var rsa = _createRsa();
        try
        {
            rsa.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char>.Empty, encryptedPkcs8PrivateKey, out _);
            return (rsa, SigningKeyType.Rsa);
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
        }
        catch
        {
            // This handle must never leak regardless of what gets thrown.
            rsa.Dispose();
            throw;
        }

        var ecdsa = _createEcdsa();
        try
        {
            ecdsa.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char>.Empty, encryptedPkcs8PrivateKey, out _);
            return (ecdsa, SigningKeyType.Ec);
        }
        catch (CryptographicException)
        {
            ecdsa.Dispose();
            throw UnsupportedKeyTypeException(version);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    private ZeeKayDaConfigurationException UnsupportedKeyTypeException(string version) =>
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
            _ => new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.startup_failure",
                    $"An unexpected error occurred reading Key Vault certificate '{_certificateName}' in vault " +
                    $"'{_vaultUri}' (HTTP {ex.Status}" + (ex.ErrorCode is null ? "" : $", ErrorCode: {ex.ErrorCode}") +
                    $"): {ex.Message}")),
        };

    private ZeeKayDaConfigurationException MapUnexpectedFailure(Exception ex) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.azure_key_vault.startup_failure",
            $"An unexpected error occurred reading Key Vault certificate '{_certificateName}' in vault " +
            $"'{_vaultUri}': {ex.Message}"));
}
