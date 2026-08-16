using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A development-only <see cref="IJwtSigningService"/> that generates an ephemeral RSA key on
/// startup, with optional persistence to a local file so that tokens survive application restarts.
/// </summary>
/// <remarks>
/// Not suitable for production; registered via <c>AddInMemoryDevelopmentJwtSigningKeys()</c> or
/// <c>AddPersistedDevelopmentJwtSigningKeys()</c>. The environment gate is enforced here via
/// <see cref="DevelopmentSigningKeyGate.Enforce"/> so the hard fail holds even when
/// <c>DevelopmentSigningKeyWarningService</c> is not running (e.g. direct construction in unit
/// tests); the gate is skipped when <see cref="DevelopmentSigningKeyOptions.EnvironmentName"/> is
/// <see langword="null"/> (no host).
/// <para>
/// This is a degenerate <see cref="KeySetOptions"/> provider: exactly one key, active from startup,
/// with no rotation use-case — rotating an ephemeral key would silently invalidate all tokens
/// issued during the process's lifetime so far.
/// </para>
/// </remarks>
internal sealed class DevelopmentJwtSigningService
    : JwtSigningService<DevelopmentSigningKeyOptions>
{
    // Minimum RSA key size per NIST SP 800-57 Part 1 Rev. 5 §5.6.1 Table 2.
    private const int MinimumRsaKeySize = 3072;

    // Key file name within the persistence directory.
    private const string KeyFileName = "dev-signing-key.pem";

    // Stable provider-internal identifier for the single dev key. Never the JWKS/JWS kid — the
    // base class derives that from the public key material.
    private static readonly KeyId DevKeyId = new("development");

    private readonly IOptions<DevelopmentSigningKeyOptions> _devOptions;
    private readonly IDevelopmentSigningKeyFileSystem _fileSystem;

    // Holds the RSA key generated/loaded by ListKeysAsync until CreateSignerAsync claims it via
    // Interlocked.Exchange, transferring ownership to the LocalSigner it returns.
    private RSA? _pendingPrivateKey;

    public DevelopmentJwtSigningService(
        IOptions<DevelopmentSigningKeyOptions> devOptions,
        TimeProvider timeProvider,
        IDevelopmentSigningKeyFileSystem fileSystem,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<DevelopmentSigningKeyOptions>> logger)
        : base(devOptions, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        _devOptions = devOptions;
        _fileSystem = fileSystem;
    }

    /// <inheritdoc/>
    protected override async ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
    {
        // RSA.Create is CPU-bound with no async variant, so key generation cannot be cancelled.
        DevelopmentSigningKeyGate.Enforce(
            _devOptions.Value.EnvironmentName,
            _devOptions.Value.AllowedDevelopmentJwtSigningKeysEnvironments);

        var persistDir = _devOptions.Value.PersistToDirectory;
        var rsa = persistDir is not null
            ? await LoadOrGeneratePersistedKeyAsync(persistDir, cancellationToken).ConfigureAwait(false)
            : GenerateEphemeralKey();

        // Compute the public key parameters before stashing the private key reference, so that a
        // failure here leaves _pendingPrivateKey untouched rather than holding a key nothing will
        // ever claim or dispose.
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));

        _pendingPrivateKey = rsa;

        // ActivateAt = null: the single dev key is active from startup (the degenerate KeySetOptions
        // case). ExpiresAt = MaxValue: a dev key never hard-expires — its lifetime is the
        // process's, not a certificate's.
        var listing = new KeyListing(DevKeyId, SigningAlgorithm.RS256, publicKey, ActivateAt: null, ExpiresAt: DateTimeOffset.MaxValue);
        return [listing];
    }

    /// <inheritdoc/>
    protected override ValueTask OnDisposeAsync()
    {
        // If ListKeysAsync generated/loaded a key but CreateSignerAsync never claimed it, the key
        // would otherwise leak until GC finalization instead of being disposed/zeroized.
        Interlocked.Exchange(ref _pendingPrivateKey, null)?.Dispose();

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    protected override ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
    {
        var rsa = Interlocked.Exchange(ref _pendingPrivateKey, null)
            ?? throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}' but no pending private " +
                $"key is available. This dev-only provider expects {nameof(CreateSignerAsync)} to be " +
                $"called at most once, immediately after {nameof(ListKeysAsync)} generated or loaded " +
                "the single dev key.");

        return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, rsa));
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
}
