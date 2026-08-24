using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A development-only <see cref="ISigningKeySource"/> that generates an ephemeral RSA key on
/// startup, with optional persistence to a local file so that tokens survive application restarts.
/// </summary>
/// <remarks>
/// Not suitable for production; registered via <c>AddInMemoryDevelopmentJwtSigningKeys()</c> or
/// <c>AddPersistedDevelopmentJwtSigningKeys()</c>. The environment gate is enforced here via
/// <see cref="DevelopmentSigningKeyGate.Enforce"/> so the hard fail holds even when
/// <c>DevelopmentSigningKeyWarningService</c> is not running (e.g. direct construction in unit
/// tests); the gate is skipped when <see cref="DevelopmentSigningKeyOptions.EnvironmentName"/> is
/// <see langword="null"/> (no host).
/// </remarks>
internal sealed class DevelopmentSigningKeySource : ISigningKeySource, IDisposable
{
    // Minimum RSA key size per NIST SP 800-57 Part 1 Rev. 5 §5.6.1 Table 2.
    private const int MinimumRsaKeySize = 3072;

    // Key file name within the persistence directory.
    private const string KeyFileName = "dev-signing-key.pem";

    // Stable source-internal identifier for the single dev key. Never the JWKS/JWS kid — the ring
    // derives that from the public key material.
    private static readonly SourceKeyId DevKeyId = new("development");

    private readonly IOptions<DevelopmentSigningKeyOptions> _options;
    private readonly IDevelopmentSigningKeyFileSystem _fileSystem;

    // Holds the RSA key generated/loaded by ReadAsync until CreateSignerAsync claims it via
    // Interlocked.Exchange, transferring ownership to the LocalSigner it returns.
    private RSA? _pendingPrivateKey;

    public DevelopmentSigningKeySource(
        IOptions<DevelopmentSigningKeyOptions> options,
        IDevelopmentSigningKeyFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fileSystem);

        _options = options;
        _fileSystem = fileSystem;
    }

    /// <inheritdoc/>
    public async ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
    {
        // RSA.Create is CPU-bound with no async variant, so key generation cannot be cancelled.
        DevelopmentSigningKeyGate.Enforce(
            _options.Value.EnvironmentName,
            _options.Value.AllowedDevelopmentJwtSigningKeysEnvironments);

        var persistDir = _options.Value.PersistToDirectory;
        var rsa = persistDir is not null
            ? await LoadOrGeneratePersistedKeyAsync(persistDir, cancellationToken).ConfigureAwait(false)
            : GenerateEphemeralKey();

        SourceKey key;
        try
        {
            // ExpiresAt = null: a dev key never expires — its lifetime is the process's, not a
            // certificate's.
            key = new SourceKey(
                DevKeyId,
                SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(false)),
                ExpiresAt: null);
        }
        catch
        {
            // Nothing will ever claim this key through CreateSignerAsync, so dispose it here rather
            // than leaving it to finalization.
            rsa.Dispose();
            throw;
        }

        // Replacing rather than assigning keeps a second read from orphaning the first read's key.
        Interlocked.Exchange(ref _pendingPrivateKey, rsa)?.Dispose();

        return SourceKeySet.Create(previous: null, current: key, next: null);
    }

    /// <inheritdoc/>
    public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        var rsa = Interlocked.Exchange(ref _pendingPrivateKey, null)
            ?? throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}' but no pending private " +
                $"key is available. This dev-only source expects {nameof(CreateSignerAsync)} to be " +
                $"called at most once, immediately after {nameof(ReadAsync)} generated or loaded the " +
                "single dev key.");

        return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, rsa));
    }

    /// <summary>
    /// Disposes the generated or loaded key when <see cref="CreateSignerAsync"/> never claimed it.
    /// </summary>
    /// <remarks>
    /// A claimed key belongs to the <see cref="LocalSigner"/> handed out for it, which the ring
    /// disposes before it disposes this source, so this never double-disposes.
    /// </remarks>
    public void Dispose() => Interlocked.Exchange(ref _pendingPrivateKey, null)?.Dispose();

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
