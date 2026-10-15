using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>A development-only source of one RSA key, generated at startup and optionally persisted to a local file.</summary>
/// <remarks>
/// Enforces the environment gate itself, so it holds even when the startup verifier does not run.
/// </remarks>
internal sealed class DevelopmentSigningKeySource(
    IOptions<DevelopmentSigningOptions> options,
    IDevelopmentSigningKeyFileSystem fileSystem) : ISigningKeySource, IDisposable
{
    // Minimum RSA key size per NIST SP 800-57 Part 1 Rev. 5 §5.6.1 Table 2.
    private const int MinimumRsaKeySize = 3072;

    private const string KeyFileName = "dev-signing-key.pem";

    private static readonly SourceKeyId DevKeyId = new("development");

    // Generates or loads the key exactly once. Never disposed: a read in flight at shutdown would throw
    // from its own Release, and strand any reader queued behind it.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // Held until CreateSignerAsync hands it to the LocalSigner it returns.
    private RSA? _pendingPrivateKey;

    // Every read returns the first listing: a fresh key per read would invalidate every issued token.
    private SourceKeyListing? _listing;

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;

    /// <inheritdoc/>
    public async Task<SourceKeyListing> ReadAsync(CancellationToken cancellationToken = default)
    {
        // On every read, ahead of the memoized listing.
        DevelopmentSigningKeyGate.Enforce(
            options.Value.EnvironmentName,
            options.Value.AllowedEnvironments);

        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_listing is not null)
                return _listing;

            // RSA.Create is CPU-bound with no async variant, so key generation cannot be cancelled.
            var persistDir = options.Value.PersistToDirectory;
            var rsa = persistDir is not null
                ? await LoadOrGeneratePersistedKeyAsync(persistDir, cancellationToken).ConfigureAwait(false)
                : GenerateEphemeralKey();

            try
            {
                // Undated and never expiring: the one dev key signs at once, for the process's lifetime.
                var key = new SourceKey(
                    DevKeyId,
                    PublicKeyParameters.FromRsa(rsa.ExportParameters(false)));

                // Built before the key is published, so a failure never leaves a disposed key to lend.
                var listing = new SourceKeyListing([key], []);

                _pendingPrivateKey = rsa;
                _listing = listing;

                return listing;
            }
            catch
            {
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

        return Task.FromResult<ISigner>(new LocalSigner(Algorithm, rsa));
    }

    /// <summary>Disposes the key when no signer claimed it; a claimed key is the signer's to dispose.</summary>
    public void Dispose() => Interlocked.Exchange(ref _pendingPrivateKey, null)?.Dispose();

    private static RSA GenerateEphemeralKey() => RSA.Create(MinimumRsaKeySize);

    private async ValueTask<RSA> LoadOrGeneratePersistedKeyAsync(string directory, CancellationToken cancellationToken)
    {
        fileSystem.EnsureDirectorySafe(directory);

        var keyPath = Path.Join(directory, KeyFileName);

        if (fileSystem.FileExists(keyPath))
            return await LoadKeyFromFileAsync(keyPath, cancellationToken).ConfigureAwait(false);

        using (var generated = RSA.Create(MinimumRsaKeySize))
            await WriteKeyAsync(generated, keyPath, cancellationToken).ConfigureAwait(false);

        // Loaded back: another host may have written the key first, and every host signs with the one on disk.
        return await LoadKeyFromFileAsync(keyPath, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask WriteKeyAsync(RSA rsa, string keyPath, CancellationToken cancellationToken)
    {
        // A 3072-bit RSA PKCS#1 PEM is at most ~3500 chars; 4096 is a safe upper bound.
        const int MaxPemChars = 4096;
        var pemBuffer = ArrayPool<char>.Shared.Rent(MaxPemChars);
        try
        {
            if (!rsa.TryExportRSAPrivateKeyPem(pemBuffer, out var pemLength))
                throw new InvalidOperationException("Failed to export RSA private key as PEM.");

            await fileSystem.WriteKeyFileAsync(keyPath, pemBuffer.AsMemory(0, pemLength), cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            pemBuffer.AsSpan().Clear();
            ArrayPool<char>.Shared.Return(pemBuffer);
        }
    }

    private async ValueTask<RSA> LoadKeyFromFileAsync(string keyPath, CancellationToken cancellationToken)
    {
        using var keyFile = await fileSystem.ReadKeyFileAsync(keyPath, cancellationToken).ConfigureAwait(false);
        var rsa = RSA.Create();
        try
        {
            // A rented char[], zeroed after import, rather than an immutable string on the heap.
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
