using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A development-only <see cref="IJwtSigningService"/> that generates an ephemeral RSA key on
/// startup, with optional persistence to a local file so that tokens survive application restarts.
/// </summary>
/// <remarks>
/// <para>
/// This provider is not suitable for production. It is registered via
/// <c>AddDevelopmentJwtSigningKeys()</c>.
/// </para>
/// <para>
/// The environment gate (hard fail outside Development) and startup warning are enforced by
/// <c>DevelopmentSigningKeyWarningService</c> (an <c>IHostedService</c> registered alongside
/// this provider). This provider's only responsibility is loading the key material.
/// </para>
/// </remarks>
internal sealed class DevelopmentJwtSigningService
    : JwtSigningService<DevelopmentSigningKeyOptions>
{
    // Minimum RSA key size per NIST SP 800-57 Part 1 Rev. 5 §5.6.1 Table 2.
    private const int MinimumRsaKeySize = 3072;

    // Key file name within the persistence directory.
    private const string KeyFileName = "dev-signing-key.pem";

    private readonly IOptions<DevelopmentSigningKeyOptions> _devOptions;
    private readonly ISigningKeyFileSystem _fileSystem;

    public DevelopmentJwtSigningService(
        IOptions<DevelopmentSigningKeyOptions> devOptions,
        TimeProvider timeProvider,
        ISigningKeyFileSystem fileSystem)
        : base(devOptions, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        _devOptions = devOptions;
        _fileSystem = fileSystem;
    }

    /// <inheritdoc/>
    protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var persistDir = _devOptions.Value.PersistToDirectory;
        var rsa = persistDir is not null
            ? LoadOrGeneratePersistedKey(persistDir)
            : GenerateEphemeralKey();

        var kid = ComputeKid(rsa);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
        var entry = new SigningKeyEntry(descriptor, 0);
        var set = new SigningKeySet([entry], [rsa]);

        return ValueTask.FromResult(set);
    }

    private static RSA GenerateEphemeralKey() => RSA.Create(MinimumRsaKeySize);

    private RSA LoadOrGeneratePersistedKey(string directory)
    {
        _fileSystem.EnsureDirectorySafe(directory);

        var keyPath = Path.Combine(directory, KeyFileName);

        if (_fileSystem.FileExists(keyPath))
            return LoadKeyFromFile(keyPath);

        var rsa = RSA.Create(MinimumRsaKeySize);
        try
        {
            _fileSystem.WriteKeyFile(keyPath, rsa.ExportRSAPrivateKeyPem());
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private RSA LoadKeyFromFile(string keyPath)
    {
        var pem = _fileSystem.ReadKeyFile(keyPath);
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static string ComputeKid(RSA rsa)
    {
        // Derive a stable kid from the public key's SHA-256 thumbprint (base64url-encoded).
        var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(publicKeyBytes);
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
