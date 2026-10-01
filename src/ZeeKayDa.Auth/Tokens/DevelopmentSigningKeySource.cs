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
/// Not suitable for production; registered via <c>AddInMemoryDevelopmentSigning()</c> or
/// <c>AddPersistedDevelopmentSigning()</c>. The environment gate is enforced here via
/// <see cref="DevelopmentSigningKeyGate.Enforce"/> so the hard fail holds even when
/// <c>DevelopmentSigningKeyVerifier</c> is not running, and it refuses when the environment
/// is unknown.
/// </remarks>
internal sealed class DevelopmentSigningKeySource(
    IOptions<DevelopmentSigningOptions> options,
    IDevelopmentSigningKeyFileSystem fileSystem) : ISigningKeySource, IDisposable
{
    // Minimum RSA key size per NIST SP 800-57 Part 1 Rev. 5 §5.6.1 Table 2.
    private const int MinimumRsaKeySize = 3072;

    // Key file name within the persistence directory.
    private const string KeyFileName = "dev-signing-key.pem";

    // Stable source-internal identifier for the single dev key. Never the JWKS/JWS kid — the ring
    // derives that from the public key material.
    private static readonly SourceKeyId DevKeyId = new("development");

    // Serialises reads so the key is generated or loaded exactly once even if two callers read
    // concurrently — "only the ring calls this" is not something this type can enforce. Deliberately
    // not disposed: disposing it would make a read that is already in flight at shutdown throw from
    // its own Release, and would strand any reader queued behind it forever.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // Holds the RSA key generated/loaded by ReadAsync until CreateSignerAsync claims it via
    // Interlocked.Exchange, transferring ownership to the LocalSigner it returns.
    private RSA? _pendingPrivateKey;

    // The one key set this source ever reports. Every read after the first returns it unchanged: a
    // fresh key per read would invalidate every token already issued under the previous one.
    private SourceKeySet? _keySet;

    /// <inheritdoc/>
    public async Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
    {
        // Enforced on every read, ahead of the memoized set, so a gate that would reject this host
        // rejects it however often the source is read.
        DevelopmentSigningKeyGate.Enforce(
            options.Value.EnvironmentName,
            options.Value.AllowedEnvironments);

        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_keySet is not null)
                return _keySet;

            // RSA.Create is CPU-bound with no async variant, so key generation cannot be cancelled.
            var persistDir = options.Value.PersistToDirectory;
            var rsa = persistDir is not null
                ? await LoadOrGeneratePersistedKeyAsync(persistDir, cancellationToken).ConfigureAwait(false)
                : GenerateEphemeralKey();

            try
            {
                // ExpiresAt = null: a dev key never expires — its lifetime is the process's, not a
                // certificate's.
                var key = new SourceKey(
                    DevKeyId,
                    SigningAlgorithm.RS256,
                    PublicKeyParameters.FromRsa(rsa.ExportParameters(false)),
                    ExpiresAt: null);

                // The set is built before the private key is published, so a failure here can never
                // leave a disposed key behind for CreateSignerAsync to lend.
                var keySet = SourceKeySet.Create(previous: null, current: key, next: null);

                _pendingPrivateKey = rsa;
                _keySet = keySet;

                return keySet;
            }
            catch
            {
                // Nothing will ever claim this key through CreateSignerAsync, so dispose it here
                // rather than leaving it to finalization.
                rsa.Dispose();
                throw;
            }
        }
        finally
        {
            _readGate.Release();
        }
    }

    /// <inheritdoc/>
    public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        if (id != DevKeyId)
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which this source did " +
                $"not report. The only key it ever reports is '{DevKeyId.Value}'.");
        }

        var rsa = Interlocked.Exchange(ref _pendingPrivateKey, null)
            ?? throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}' but no pending private " +
                $"key is available. This dev-only source expects {nameof(CreateSignerAsync)} to be " +
                $"called at most once, immediately after {nameof(ReadAsync)} generated or loaded the " +
                "single dev key.");

        return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, rsa));
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
        fileSystem.EnsureDirectorySafe(directory);

        var keyPath = Path.Join(directory, KeyFileName);

        if (fileSystem.FileExists(keyPath))
            return await LoadKeyFromFileAsync(keyPath, cancellationToken).ConfigureAwait(false);

        var rsa = RSA.Create(MinimumRsaKeySize);
        bool written;
        try
        {
            // A 3072-bit RSA PKCS#1 PEM is at most ~3500 chars; 4096 is a safe upper bound.
            const int MaxPemChars = 4096;
            var pemBuffer = ArrayPool<char>.Shared.Rent(MaxPemChars);
            try
            {
                if (!rsa.TryExportRSAPrivateKeyPem(pemBuffer, out var pemLength))
                    throw new InvalidOperationException("Failed to export RSA private key as PEM.");
                written = await fileSystem.WriteKeyFileAsync(keyPath, pemBuffer.AsMemory(0, pemLength), cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                pemBuffer.AsSpan().Clear();
                ArrayPool<char>.Shared.Return(pemBuffer);
            }
        }
        catch
        {
            rsa.Dispose();
            throw;
        }

        if (written)
            return rsa;

        // Another host created the key between the existence check and this write. Its key is the
        // one on disk, so it is the one used: every host sharing the folder signs with the same key.
        rsa.Dispose();
        return await LoadKeyFromFileAsync(keyPath, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<RSA> LoadKeyFromFileAsync(string keyPath, CancellationToken cancellationToken)
    {
        using var keyFile = await fileSystem.ReadKeyFileAsync(keyPath, cancellationToken).ConfigureAwait(false);
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
