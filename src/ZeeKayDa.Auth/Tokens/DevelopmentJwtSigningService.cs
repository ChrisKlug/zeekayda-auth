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
/// <para>
/// This provider is not suitable for production. It is registered via
/// <c>AddInMemoryDevelopmentJwtSigningKeys()</c> or <c>AddPersistedDevelopmentJwtSigningKeys()</c>.
/// </para>
/// <para>
/// The environment gate is enforced here via <see cref="DevelopmentSigningKeyGate.Enforce"/>
/// so that the hard fail holds even if <c>DevelopmentSigningKeyWarningService</c> is not running
/// (e.g. direct construction in unit tests). <c>DevelopmentSigningKeyWarningService</c> also
/// calls the same gate helper, so the logic is not duplicated.
/// The environment name is read from <see cref="DevelopmentSigningKeyOptions.EnvironmentName"/>;
/// when <see langword="null"/> (no host, unit-test scenario), the gate is skipped. The allowed
/// environments list is read from
/// <see cref="DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/> — a
/// provider-scoped, code-only opt-in, not a server-wide setting (ADR 0011 §2).
/// </para>
/// <para>
/// This is a degenerate ADR 0015 Tier A (<see cref="KeySetOptions"/>) provider: exactly one key,
/// with no <see cref="KeyListing.ActivateAt"/>, active from startup. <see cref="ListKeysAsync"/>
/// is called exactly once for the lifetime of the service instance (per the base class's Tier A
/// contract), which is also where the dev key is generated or loaded — there is no rotation
/// use-case for dev keys; rotating an ephemeral key would silently invalidate all tokens issued
/// during the process's lifetime so far.
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
    // base class derives that from the public key material (ADR 0015 §2).
    private static readonly KeyId DevKeyId = new("development");

    private readonly IOptions<DevelopmentSigningKeyOptions> _devOptions;
    private readonly IDevelopmentSigningKeyFileSystem _fileSystem;

    // Holds the RSA key generated/loaded by ListKeysAsync until CreateSignerAsync claims it.
    // ListKeysAsync runs exactly once for a Tier A provider (JwtSigningService<TOptions>'s
    // contract), so this is populated at most once; CreateSignerAsync consumes it exactly once
    // via Interlocked.Exchange, transferring ownership to the LocalSigner it returns.
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
        // CancellationToken is propagated to all file I/O calls below.
        // RSA.Create is CPU-bound and has no async variant, so key generation cannot be cancelled.

        // Environment gate — enforced here so the check holds even when DevelopmentSigningKeyWarningService
        // is not running (e.g. direct construction in unit tests). EnvironmentName is null when the
        // service is constructed directly without a host; the gate is intentionally skipped in that case.
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

        // ActivateAt = null: the single dev key is active from startup (ADR 0015 §1's degenerate
        // Tier A case). ExpiresAt = MaxValue: a dev key never hard-expires — its lifetime is the
        // process's, not a certificate's.
        var listing = new KeyListing(DevKeyId, SigningAlgorithm.RS256, publicKey, ActivateAt: null, ExpiresAt: DateTimeOffset.MaxValue);
        return [listing];
    }

    /// <inheritdoc/>
    protected override ValueTask DisposeAsyncCore()
    {
        // If ListKeysAsync generated/loaded a key but CreateSignerAsync never claimed it (e.g. this
        // instance's lifetime only ever served ListKeysAsync/JWKS listing, never a signing call),
        // the key would otherwise leak until GC finalization instead of being disposed/zeroized.
        Interlocked.Exchange(ref _pendingPrivateKey, null)?.Dispose();

        return base.DisposeAsyncCore();
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
