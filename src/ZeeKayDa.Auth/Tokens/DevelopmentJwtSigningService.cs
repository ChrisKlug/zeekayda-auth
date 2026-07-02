using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
/// <para>
/// Dev keys are generated once and memoized. Unlike production providers, there is no
/// rotation use-case for dev keys; rotating an ephemeral key would silently invalidate all
/// tokens issued within the first refresh interval of the process lifetime.
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
    private readonly IDevelopmentSigningKeyFileSystem _fileSystem;

    // Memoized on first call — dev keys are never rotated within a process lifetime.
    private SigningKeySet? _memoizedSet;

    public DevelopmentJwtSigningService(
        IOptions<DevelopmentSigningKeyOptions> devOptions,
        TimeProvider timeProvider,
        IDevelopmentSigningKeyFileSystem fileSystem)
        : base(devOptions, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        _devOptions = devOptions;
        _fileSystem = fileSystem;
    }

    /// <inheritdoc/>
    protected override async ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        // CancellationToken is propagated to all file I/O calls below.
        // RSA.Create is CPU-bound and has no async variant, so key generation cannot be cancelled.
        if (_memoizedSet is not null)
            return _memoizedSet;

        var persistDir = _devOptions.Value.PersistToDirectory;
        var rsa = persistDir is not null
            ? await LoadOrGeneratePersistedKeyAsync(persistDir, cancellationToken).ConfigureAwait(false)
            : GenerateEphemeralKey();

        var kid = ComputeKid(rsa);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
        var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa }]);

        _memoizedSet = set;
        return set;
    }

    private static RSA GenerateEphemeralKey() => RSA.Create(MinimumRsaKeySize);

    private async ValueTask<RSA> LoadOrGeneratePersistedKeyAsync(string directory, CancellationToken cancellationToken)
    {
        _fileSystem.EnsureDirectorySafe(directory);

        var keyPath = Path.Join(directory, KeyFileName);

        if (_fileSystem.FileExists(keyPath))
            return await LoadKeyFromFileAsync(keyPath, cancellationToken).ConfigureAwait(false);

        var rsa = RSA.Create(MinimumRsaKeySize);
        try
        {
            await _fileSystem.WriteKeyFileAsync(keyPath, rsa.ExportRSAPrivateKeyPem(), cancellationToken).ConfigureAwait(false);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private async ValueTask<RSA> LoadKeyFromFileAsync(string keyPath, CancellationToken cancellationToken)
    {
        using var keyFile = await _fileSystem.ReadKeyFileAsync(keyPath, cancellationToken).ConfigureAwait(false);
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(Encoding.UTF8.GetString(keyFile.Bytes));
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
        // RFC 7638 JWK Thumbprint: SHA-256 of the canonical JSON of the minimal RSA JWK member
        // set, with members in lexicographic order, no whitespace.
        // For RSA: {"e":"<b64url(e)>","kty":"RSA","n":"<b64url(n)>"}
        // This matches what external tools (jose-jwt, python-jose, online JWK inspectors) compute,
        // so developers can correlate a kid in a token header to a key in a JWKS without confusion.
        var rsaParams = rsa.ExportParameters(false);
        var e = Base64UrlEncode(rsaParams.Exponent!);
        var n = Base64UrlEncode(rsaParams.Modulus!);

        // Use Utf8JsonWriter to produce the canonical JSON bytes without intermediate string allocation.
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteString("e", e);
            writer.WriteString("kty", "RSA");
            writer.WriteString("n", n);
            writer.WriteEndObject();
        }

        var hash = SHA256.HashData(buffer.WrittenSpan);
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        var encoded = new byte[Base64Url.GetEncodedLength(input.Length)];
        Base64Url.EncodeToUtf8(input, encoded);
        return Encoding.ASCII.GetString(encoded);
    }
}
