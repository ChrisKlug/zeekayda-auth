using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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
/// <para>
/// Azure Key Vault's <c>KeyClient.GetKeyAsync</c> never returns private key material, regardless
/// of a key's exportable flag — that is the mechanism the remote-signing provider uses, and it is
/// public-key-only by design (see <see cref="KeyVaultKeyReader"/>). True private key export
/// requires downloading the certificate's linked secret instead: every Key Vault certificate has
/// an addressable secret sharing its name, and — only when the certificate's key policy is
/// exportable — that secret's value contains the full PFX (certificate plus private key).
/// </para>
/// <para>
/// Every <see cref="Azure.RequestFailedException"/> and other transport fault raised by the
/// underlying SDK is mapped here to a <see cref="ZeeKayDaConfigurationException"/> carrying a
/// stable failure code and enough context (vault, certificate name, HTTP status, SDK error code)
/// to be actionable, without ever including key material.
/// </para>
/// <para>
/// The downloaded PFX is parsed with <see cref="Pkcs12Info"/> — a pure managed ASN.1/PKCS#12
/// parser — rather than <c>X509CertificateLoader.LoadPkcs12</c>. The latter always constructs an
/// OS-backed <c>X509Certificate2</c>, and on macOS there is no way to do that without writing the
/// private key to a transient keychain on disk: <c>X509KeyStorageFlags.EphemeralKeySet</c> throws
/// <see cref="PlatformNotSupportedException"/> there rather than honoring the "never touch disk"
/// contract. Parsing the PKCS#12 structure directly and importing the key bag straight into an
/// <see cref="RSA"/>/<see cref="ECDsa"/> instance keeps the private key in managed memory only, on
/// every platform, with no OS keystore involved at all.
/// </para>
/// </remarks>
internal sealed class KeyVaultCertificateReader : IKeyVaultCertificateReader
{
    // Key Vault's default (and, in practice, only realistic) content type for a managed
    // certificate's secret value. PEM-formatted secrets are a documented possibility for
    // certificates imported with a PEM policy, but supporting that format would require parsing
    // and re-assembling a PEM certificate/key chain locally — out of scope here; such a
    // certificate fails fast below with an actionable message rather than being silently mishandled.
    private const string Pkcs12ContentType = "application/x-pkcs12";

    private readonly CertificateClient _certificateClient;
    private readonly SecretClient _secretClient;
    private readonly string _certificateName;
    private readonly Uri _vaultUri;

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

            yield return new KeyVaultCertificateVersionInfo(
                current.Id,
                current.Version,
                current.Enabled ?? true,
                current.CreatedOn ?? DateTimeOffset.MinValue,
                current.NotBefore,
                current.ExpiresOn);
        }
    }

    /// <inheritdoc/>
    public async ValueTask<(AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType)> GetPrivateKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(version);

        var secret = await DownloadCertificateSecretAsync(version, cancellationToken).ConfigureAwait(false);
        return ExtractPrivateKey(secret, version);
    }

    private async ValueTask<KeyVaultSecret> DownloadCertificateSecretAsync(string version, CancellationToken cancellationToken)
    {
        try
        {
            var certificate = await _certificateClient
                .GetCertificateVersionAsync(_certificateName, version, cancellationToken)
                .ConfigureAwait(false);

            if (!KeyVaultSecretIdentifier.TryCreate(certificate.Value.SecretId, out var secretIdentifier))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.azure_key_vault.certificate_missing_secret",
                        $"Key Vault certificate '{_certificateName}' version '{version}' in vault '{_vaultUri}' " +
                        "has no linked secret identifier and cannot be used for local signing."));
            }

            var secret = await _secretClient
                .GetSecretAsync(secretIdentifier.Name, secretIdentifier.Version, cancellationToken)
                .ConfigureAwait(false);
            return secret.Value;
        }
        catch (RequestFailedException ex)
        {
            throw MapRequestFailedException(ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ZeeKayDaConfigurationException)
        {
            throw MapUnexpectedFailure(ex);
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
    /// Parses a PKCS#12 payload purely in managed memory (see the class remarks for why this is
    /// used instead of <c>X509CertificateLoader.LoadPkcs12</c>) and imports the first private key
    /// bag found into an <see cref="RSA"/> or <see cref="ECDsa"/> instance.
    /// </summary>
    private (AsymmetricAlgorithm, SigningKeyType) ExtractPrivateKeyFromPkcs12(byte[] pfxBytes, string version)
    {
        var pkcs12 = Pkcs12Info.Decode(pfxBytes, out _, skipCopy: true);

        foreach (var safeContents in pkcs12.AuthenticatedSafe)
        {
            // A Key Vault-exported PFX has no real password, but PKCS#12 treats a null password
            // and an empty-string password as distinct — Decrypt(ReadOnlySpan<char>.Empty) is the
            // "no password" case in practice for tooling that still wraps SafeContents in a
            // password-confidentiality envelope even when the caller supplied none.
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

        // Confirmed behavior (see ADR 0011 and the readiness review for this issue): when a
        // certificate's key policy is exportable: false, Key Vault's secret endpoint still returns
        // HTTP 200 with a PKCS#12 payload — it simply omits the private key bag from it entirely.
        // There is no dedicated "forbidden" error for this case, so "no key bag was found" is the
        // only reliable signal, and must be checked after every download, not assumed from policy
        // metadata (which reflects the certificate's *current* policy, not necessarily the policy a
        // specific already-issued version was created under).
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
        var rsa = RSA.Create();
        try
        {
            rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
            return (rsa, SigningKeyType.Rsa);
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
        }

        var ecdsa = ECDsa.Create();
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
    }

    private (AsymmetricAlgorithm, SigningKeyType) ImportShroudedPrivateKey(
        ReadOnlySpan<byte> encryptedPkcs8PrivateKey, string version)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char>.Empty, encryptedPkcs8PrivateKey, out _);
            return (rsa, SigningKeyType.Rsa);
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
        }

        var ecdsa = ECDsa.Create();
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
                    "). Verify the configured credential has been granted both 'certificates/get' and " +
                    "'secrets/get' permissions (via an access policy, or the 'Key Vault Certificate User' " +
                    "built-in RBAC role) on this vault — downloading a certificate's private key requires both.")),
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
