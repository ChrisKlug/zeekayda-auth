using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// Hand-rolled <see cref="IKeyVaultCertificateReader"/> test double — mirrors the house style of
/// <see cref="FakeKeyVaultKeyReader"/>, adapted for Variant B: unlike the remote-signing reader,
/// <see cref="GetPrivateKeyMaterialAsync"/> here must hand back a genuine, fully-usable
/// <see cref="AsymmetricAlgorithm"/> with real private key material, because the cached-signing
/// service signs locally with it for the active version only — <see cref="GetPublicKeyMaterialAsync"/>
/// hands back a public-only handle for every other included version. Full (private + public) key
/// material is stored per version so that a fresh, independent key object is produced on every
/// call — matching what the real <c>KeyVaultCertificateReader</c> does (a new object decoded from
/// the downloaded secret, or the downloaded certificate, on every call) and avoiding a
/// shared-instance-disposed-twice hazard when the same version is loaded more than once across a
/// test.
/// </summary>
internal sealed class FakeKeyVaultCertificateReader : IKeyVaultCertificateReader
{
    private readonly Dictionary<string, RSAParameters> _rsaMaterial = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ECParameters> _ecMaterial = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Exception> _privateKeyExceptions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Exception> _publicKeyExceptions = new(StringComparer.Ordinal);

    public List<KeyVaultCertificateVersionInfo> Versions { get; } = [];

    /// <summary>Every version passed to <see cref="GetPrivateKeyMaterialAsync"/>, in call order.</summary>
    public List<string> PrivateKeyMaterialCalls { get; } = [];

    /// <summary>Every version passed to <see cref="GetPublicKeyMaterialAsync"/>, in call order.</summary>
    public List<string> PublicKeyMaterialCalls { get; } = [];

    /// <summary>When set, <see cref="GetCertificateVersionsAsync"/> throws this instead of yielding versions.</summary>
    public Exception? VersionsException { get; set; }

    /// <summary>
    /// When set, invoked with the version and the exact key object right after
    /// <see cref="GetPrivateKeyMaterialAsync"/> extracts it — lets a test capture the live handle
    /// and later assert it was disposed (e.g. by calling <c>ExportParameters</c> on it and
    /// expecting <see cref="ObjectDisposedException"/>) if the caller fails after extraction.
    /// </summary>
    public Action<string, AsymmetricAlgorithm>? OnPrivateKeyExtracted { get; set; }

    public KeyVaultCertificateVersionInfo AddRsaVersion(
        string version,
        DateTimeOffset createdOn,
        bool enabled = true,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresOn = null,
        RSAParameters? keyMaterial = null)
    {
        RSAParameters fullParameters;
        if (keyMaterial is { } supplied)
        {
            fullParameters = supplied;
        }
        else
        {
            using var rsa = RSA.Create(2048);
            fullParameters = rsa.ExportParameters(includePrivateParameters: true);
        }

        _rsaMaterial[version] = fullParameters;

        var info = new KeyVaultCertificateVersionInfo(
            MakeVersionUri(version), version, enabled, createdOn, notBefore, expiresOn);
        Versions.Add(info);
        return info;
    }

    public KeyVaultCertificateVersionInfo AddEcVersion(
        string version,
        DateTimeOffset createdOn,
        bool enabled = true,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresOn = null,
        ECCurve? curve = null,
        ECParameters? keyMaterial = null)
    {
        ECParameters fullParameters;
        if (keyMaterial is { } supplied)
        {
            fullParameters = supplied;
        }
        else
        {
            using var ec = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
            fullParameters = ec.ExportParameters(includePrivateParameters: true);
        }

        _ecMaterial[version] = fullParameters;

        var info = new KeyVaultCertificateVersionInfo(
            MakeVersionUri(version), version, enabled, createdOn, notBefore, expiresOn);
        Versions.Add(info);
        return info;
    }

    /// <summary>Reuses another version's exact RSA key material — for kid-stability/duplicate-kid tests.</summary>
    public KeyVaultCertificateVersionInfo AddRsaVersionWithSameMaterialAs(
        string version, string sourceVersion, DateTimeOffset createdOn, bool enabled = true)
        => AddRsaVersion(version, createdOn, enabled, keyMaterial: _rsaMaterial[sourceVersion]);

    public void SetEnabled(string version, bool enabled)
    {
        var index = Versions.FindIndex(v => v.Version == version);
        var existing = Versions[index];
        Versions[index] = existing with { Enabled = enabled };
    }

    /// <summary>
    /// Configures <see cref="GetPrivateKeyMaterialAsync"/> to throw <paramref name="exception"/> for
    /// this specific version — simulates a real <c>KeyVaultCertificateReader</c> failure (non-exportable
    /// policy, access denied, unsupported content type, ...) at the private-key-download step, as
    /// opposed to the version-enumeration step (<see cref="VersionsException"/>).
    /// </summary>
    public void SetPrivateKeyException(string version, Exception exception) => _privateKeyExceptions[version] = exception;

    /// <summary>
    /// Configures <see cref="GetPublicKeyMaterialAsync"/> to throw <paramref name="exception"/> for
    /// this specific version — simulates a real <c>KeyVaultCertificateReader</c> failure (access
    /// denied, certificate not found, ...) at the public-key-download step, which every included
    /// version except the active one now goes through instead of <see cref="GetPrivateKeyMaterialAsync"/>.
    /// </summary>
    public void SetPublicKeyException(string version, Exception exception) => _publicKeyExceptions[version] = exception;

    /// <summary>Returns the public-only RSA parameters registered for <paramref name="version"/>, for kid assertions.</summary>
    public RSAParameters GetRsaMaterial(string version)
    {
        var full = _rsaMaterial[version];
        return new RSAParameters { Modulus = full.Modulus, Exponent = full.Exponent };
    }

    /// <summary>Returns the public-only EC parameters registered for <paramref name="version"/>, for kid assertions.</summary>
    public ECParameters GetEcMaterial(string version)
    {
        var full = _ecMaterial[version];
        return new ECParameters { Curve = full.Curve, Q = full.Q };
    }

    public async IAsyncEnumerable<KeyVaultCertificateVersionInfo> GetCertificateVersionsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (VersionsException is not null)
            throw VersionsException;

        foreach (var version in Versions)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            yield return version;
        }
    }

    public ValueTask<(AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType)> GetPrivateKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        PrivateKeyMaterialCalls.Add(version);

        if (_privateKeyExceptions.TryGetValue(version, out var exception))
            throw exception;

        if (_rsaMaterial.TryGetValue(version, out var rsaParams))
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(rsaParams);
                OnPrivateKeyExtracted?.Invoke(version, rsa);
                return ValueTask.FromResult<(AsymmetricAlgorithm, SigningKeyType)>((rsa, SigningKeyType.Rsa));
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        if (_ecMaterial.TryGetValue(version, out var ecParams))
        {
            var ec = ECDsa.Create();
            try
            {
                ec.ImportParameters(ecParams);
                OnPrivateKeyExtracted?.Invoke(version, ec);
                return ValueTask.FromResult<(AsymmetricAlgorithm, SigningKeyType)>((ec, SigningKeyType.Ec));
            }
            catch
            {
                ec.Dispose();
                throw;
            }
        }

        throw new KeyNotFoundException($"No fake certificate private key material registered for version '{version}'.");
    }

    public ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetPublicKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        PublicKeyMaterialCalls.Add(version);

        if (_publicKeyExceptions.TryGetValue(version, out var exception))
            throw exception;

        if (_rsaMaterial.TryGetValue(version, out var rsaParams))
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(new RSAParameters { Modulus = rsaParams.Modulus, Exponent = rsaParams.Exponent });
                return ValueTask.FromResult<(AsymmetricAlgorithm, SigningKeyType)>((rsa, SigningKeyType.Rsa));
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        if (_ecMaterial.TryGetValue(version, out var ecParams))
        {
            var ec = ECDsa.Create();
            try
            {
                ec.ImportParameters(new ECParameters { Curve = ecParams.Curve, Q = ecParams.Q });
                return ValueTask.FromResult<(AsymmetricAlgorithm, SigningKeyType)>((ec, SigningKeyType.Ec));
            }
            catch
            {
                ec.Dispose();
                throw;
            }
        }

        throw new KeyNotFoundException($"No fake certificate public key material registered for version '{version}'.");
    }

    private static Uri MakeVersionUri(string version) =>
        new($"https://fake-vault.vault.azure.net/certificates/fake-cert/{version}");
}
