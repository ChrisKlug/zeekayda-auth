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
/// The environment gate is enforced here as a hard fail — mirroring the logic in
/// <c>DevelopmentSigningKeyWarningService</c> — so that the gate holds even if the hosted
/// service is not running (e.g. in unit test hosts). The startup warning and pre-warm are
/// handled by <c>DevelopmentSigningKeyWarningService</c>.
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
    private readonly IOptions<AuthorizationServerOptions> _serverOptions;
    private readonly IDevelopmentSigningKeyFileSystem _fileSystem;

    // Memoized on first call — dev keys are never rotated within a process lifetime.
    private SigningKeySet? _memoizedSet;

    public DevelopmentJwtSigningService(
        IOptions<DevelopmentSigningKeyOptions> devOptions,
        IOptions<AuthorizationServerOptions> serverOptions,
        TimeProvider timeProvider,
        IDevelopmentSigningKeyFileSystem fileSystem)
        : base(devOptions, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(fileSystem);
        _devOptions = devOptions;
        _serverOptions = serverOptions;
        _fileSystem = fileSystem;
    }

    /// <inheritdoc/>
    protected override async ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        // CancellationToken is propagated to all file I/O calls below.
        // RSA.Create is CPU-bound and has no async variant, so key generation cannot be cancelled.

        // Environment gate — mirror the logic in DevelopmentSigningKeyWarningService so that the
        // hard fail is enforced at the point of key use, independent of whether the hosted service
        // has run. The environment name is injected via DevelopmentSigningKeyOptions so that the
        // core project does not need to take a dependency on Microsoft.Extensions.Hosting.Abstractions.
        var currentEnvironment = _devOptions.Value.EnvironmentName;

        if (currentEnvironment is not null)
        {
            // Production is always a hard fail, regardless of AllowedDevelopmentJwtSigningKeysEnvironments.
            var isProduction = string.Equals(currentEnvironment, "Production", StringComparison.OrdinalIgnoreCase);
            if (isProduction)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.production_environment",
                        "Development signing keys are active in a Production environment. " +
                        "AllowedDevelopmentJwtSigningKeysEnvironments cannot include the Production environment. " +
                        "Development keys are ephemeral or stored in a local file and are not suitable for production. " +
                        "Replace AddDevelopmentJwtSigningKeys() with a production key provider."));
            }

            var allowedEnvironments = _serverOptions.Value.AllowedDevelopmentJwtSigningKeysEnvironments;
            var isAllowed = allowedEnvironments.Any(e =>
                string.Equals(e, currentEnvironment, StringComparison.OrdinalIgnoreCase));

            if (!isAllowed)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.non_development",
                        $"Development signing keys are active in environment '{currentEnvironment}', " +
                        "which is not in AllowedDevelopmentJwtSigningKeysEnvironments. " +
                        "This is a configuration error: development keys are ephemeral or stored in a " +
                        "local file and are not suitable for production. " +
                        "Replace AddDevelopmentJwtSigningKeys() with a production key provider, or add " +
                        "the environment name to AllowedDevelopmentJwtSigningKeysEnvironments if this is " +
                        "an intentional non-Development test host (e.g. an integration test host)."));
            }
        }

        if (_memoizedSet is not null)
            return _memoizedSet;

        var persistDir = _devOptions.Value.PersistToDirectory;
        var rsa = persistDir is not null
            ? await LoadOrGeneratePersistedKeyAsync(persistDir, cancellationToken).ConfigureAwait(false)
            : GenerateEphemeralKey();

        var rsaParams = rsa.ExportParameters(false);
        var kid = ComputeKid(rsaParams);
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
            // A 3072-bit RSA PKCS#1 PEM is at most ~3500 chars; 4096 is a safe upper bound.
            const int MaxPemChars = 4096;
            var pemBuffer = ArrayPool<char>.Shared.Rent(MaxPemChars);
            try
            {
                if (!rsa.TryExportRSAPrivateKeyPem(pemBuffer, out var written))
                    throw new InvalidOperationException("Failed to export RSA private key as PEM.");
                await _fileSystem.WriteKeyFileAsync(keyPath, pemBuffer.AsMemory(0, written), cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                pemBuffer.AsSpan().Clear();
                ArrayPool<char>.Shared.Return(pemBuffer);
            }

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
            // Decode the PEM bytes into a rented char[] so the private key material can be
            // zeroed after import rather than lingering on the heap as an immutable string.
            var charCount = Encoding.UTF8.GetCharCount(keyFile.Bytes);
            var charBuffer = ArrayPool<char>.Shared.Rent(charCount);
            try
            {
                Encoding.UTF8.GetChars(keyFile.Bytes, charBuffer.AsSpan(0, charCount));
                rsa.ImportFromPem(charBuffer.AsSpan(0, charCount));
            }
            finally
            {
                charBuffer.AsSpan().Clear();
                ArrayPool<char>.Shared.Return(charBuffer);
            }

            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static string ComputeKid(RSAParameters rsaParams)
    {
        // RFC 7638 JWK Thumbprint: SHA-256 of the canonical JSON of the minimal RSA JWK member
        // set, with members in lexicographic order, no whitespace.
        // For RSA: {"e":"<b64url(e)>","kty":"RSA","n":"<b64url(n)>"}
        // This matches what external tools (jose-jwt, python-jose, online JWK inspectors) compute,
        // so developers can correlate a kid in a token header to a key in a JWKS without confusion.
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
