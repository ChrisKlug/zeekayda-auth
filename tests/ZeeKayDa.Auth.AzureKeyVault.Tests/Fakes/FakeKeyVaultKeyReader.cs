using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// Hand-rolled <see cref="IKeyVaultKeyReader"/> test double — mirrors the house style of
/// <c>InMemorySigningKeyFileSystem</c> in <c>DevelopmentJwtSigningServiceTests</c>. Key material
/// is stored as exportable public parameters (not live <see cref="AsymmetricAlgorithm"/> objects)
/// so that <see cref="GetKeyMaterialAsync"/> can return a *fresh* object on every call — matching
/// what the real Key Vault-backed <c>KeyVaultKeyReader</c> does (a new object per SDK call) and
/// avoiding a shared-instance-disposed-twice hazard when the same version is loaded by more than
/// one short-lived <c>AzureKeyVaultRemoteSigningJwtSigningService</c> instance across a test
/// (the base class disposes the private key objects it was handed once superseded).
/// </summary>
internal sealed class FakeKeyVaultKeyReader : IKeyVaultKeyReader
{
    private readonly Dictionary<string, RSAParameters> _rsaMaterial = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ECParameters> _ecMaterial = new(StringComparer.Ordinal);

    public List<KeyVaultKeyVersionInfo> Versions { get; } = [];

    /// <summary>When set, <see cref="GetKeyVersionsAsync"/> throws this instead of yielding versions.</summary>
    public Exception? VersionsException { get; set; }

    /// <summary>When set, <see cref="GetKeyMaterialAsync"/> throws this instead of returning material.</summary>
    public Exception? MaterialException { get; set; }

    public KeyVaultKeyVersionInfo AddRsaVersion(
        string version,
        DateTimeOffset createdOn,
        bool enabled = true,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresOn = null,
        RSAParameters? keyMaterial = null)
    {
        using var rsa = keyMaterial is null ? RSA.Create(2048) : null;
        var parameters = keyMaterial ?? rsa!.ExportParameters(false);
        _rsaMaterial[version] = parameters;

        var info = new KeyVaultKeyVersionInfo(
            MakeVersionUri(version), version, enabled, createdOn, notBefore, expiresOn);
        Versions.Add(info);
        return info;
    }

    public KeyVaultKeyVersionInfo AddEcVersion(
        string version,
        DateTimeOffset createdOn,
        bool enabled = true,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresOn = null,
        ECCurve? curve = null,
        ECParameters? keyMaterial = null)
    {
        using var ec = keyMaterial is null ? ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256) : null;
        var parameters = keyMaterial ?? ec!.ExportParameters(false);
        _ecMaterial[version] = parameters;

        var info = new KeyVaultKeyVersionInfo(
            MakeVersionUri(version), version, enabled, createdOn, notBefore, expiresOn);
        Versions.Add(info);
        return info;
    }

    /// <summary>Reuses another version's exact RSA public key material — for kid-stability tests.</summary>
    public KeyVaultKeyVersionInfo AddRsaVersionWithSameMaterialAs(
        string version, string sourceVersion, DateTimeOffset createdOn, bool enabled = true)
        => AddRsaVersion(version, createdOn, enabled, keyMaterial: _rsaMaterial[sourceVersion]);

    public void SetEnabled(string version, bool enabled)
    {
        var index = Versions.FindIndex(v => v.Version == version);
        var existing = Versions[index];
        Versions[index] = existing with { Enabled = enabled };
    }

    /// <summary>Returns the public RSA parameters registered for <paramref name="version"/>, for assertions.</summary>
    public RSAParameters GetRsaMaterial(string version) => _rsaMaterial[version];

    /// <summary>Returns the public EC parameters registered for <paramref name="version"/>, for assertions.</summary>
    public ECParameters GetEcMaterial(string version) => _ecMaterial[version];

    public async IAsyncEnumerable<KeyVaultKeyVersionInfo> GetKeyVersionsAsync(
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

    public ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetKeyMaterialAsync(
        string version, CancellationToken cancellationToken)
    {
        if (MaterialException is not null)
            throw MaterialException;

        if (_rsaMaterial.TryGetValue(version, out var rsaParams))
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(rsaParams);
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
                return ValueTask.FromResult<(AsymmetricAlgorithm, SigningKeyType)>((ec, SigningKeyType.Ec));
            }
            catch
            {
                ec.Dispose();
                throw;
            }
        }

        throw new KeyNotFoundException($"No fake key material registered for version '{version}'.");
    }

    private static Uri MakeVersionUri(string version) =>
        new($"https://fake-vault.vault.azure.net/keys/fake-key/{version}");
}
