using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.MacOS.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS.Tests.Fakes;

/// <summary>
/// Hand-rolled <see cref="IKeychainItemReader"/> test double. Hands back a fresh, independent copy of
/// registered material on every call — matching what the real <see cref="KeychainItemReader"/> does
/// (a fresh native query every time) — so the caller's disposal of a returned instance never
/// invalidates what the fake holds. Mirrors <c>ZeeKayDa.Auth.Windows.Tests.Fakes.FakeCertificateStoreReader</c>.
/// </summary>
internal sealed class FakeKeychainItemReader : IKeychainItemReader
{
    private readonly Dictionary<string, X509Certificate2> _certificates = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (RSA? Rsa, ECDsa? Ec)> _keys = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Exception> _certificateExceptions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Exception> _keyExceptions = new(StringComparer.Ordinal);

    /// <summary>Every label passed to <see cref="TryGetCertificate"/>, in call order.</summary>
    public List<string> CertificateLookups { get; } = [];

    /// <summary>Every label passed to <see cref="GetKey"/>, in call order.</summary>
    public List<string> KeyLookups { get; } = [];

    /// <summary>Registers a certificate-backed item, with a private key, findable by label.</summary>
    public void AddCertificate(string label, X509Certificate2 certificate) => _certificates[label] = certificate;

    /// <summary>Registers a bare RSA key item findable by label.</summary>
    public void AddKey(string label, RSA rsa) => _keys[label] = (rsa, null);

    /// <summary>Registers a bare EC key item findable by label.</summary>
    public void AddKey(string label, ECDsa ecdsa) => _keys[label] = (null, ecdsa);

    /// <summary>When set, <see cref="TryGetCertificate"/> throws this instead of its normal behavior for this label.</summary>
    public void SetCertificateLookupException(string label, Exception exception) => _certificateExceptions[label] = exception;

    /// <summary>When set, <see cref="GetKey"/> throws this instead of its normal behavior for this label.</summary>
    public void SetKeyLookupException(string label, Exception exception) => _keyExceptions[label] = exception;

    public bool TryGetCertificate(string label, [NotNullWhen(true)] out KeychainCertificateItem? certificate)
    {
        CertificateLookups.Add(label);
        if (_certificateExceptions.TryGetValue(label, out var exception))
            throw exception;

        if (!_certificates.TryGetValue(label, out var stored))
        {
            certificate = null;
            return false;
        }

        var (signingKey, keyType) = ExtractCertificateKey(stored, label);
        certificate = new KeychainCertificateItem
        {
            Certificate = TestKeyFactory.Copy(stored),
            SigningKey = signingKey,
            KeyType = keyType,
        };
        return true;
    }

    public KeychainKeyItem GetKey(string label)
    {
        KeyLookups.Add(label);
        if (_keyExceptions.TryGetValue(label, out var exception))
            throw exception;

        if (!_keys.TryGetValue(label, out var entry))
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.macos_keychain.item_not_found",
                $"Simulated missing Keychain item '{label}'."));
        }

        if (entry.Rsa is { } rsa)
            return new KeychainKeyItem { SigningKey = TestKeyFactory.Copy(rsa), KeyType = SigningKeyType.Rsa };

        return new KeychainKeyItem { SigningKey = TestKeyFactory.Copy(entry.Ec!), KeyType = SigningKeyType.Ec };
    }

    private static (AsymmetricAlgorithm SigningKey, SigningKeyType KeyType) ExtractCertificateKey(X509Certificate2 certificate, string label)
    {
        var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
            return (rsa, SigningKeyType.Rsa);

        var ec = certificate.GetECDsaPrivateKey();
        if (ec is not null)
            return (ec, SigningKeyType.Ec);

        throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.macos_keychain.private_key_not_found",
            $"Simulated certificate '{label}' has no private key."));
    }
}
