using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

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
/// Dev keys are generated once, and <see cref="HasKeySetChangedAsync"/> is hardcoded to report
/// "unchanged" so that <see cref="LoadKeysAsync"/> is never invoked a second time for the
/// lifetime of the service instance. Unlike production providers, there is no rotation
/// use-case for dev keys; rotating an ephemeral key would silently invalidate all tokens issued
/// within the first refresh interval of the process lifetime.
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

        var rsaParams = rsa.ExportParameters(false);
        var kid = JwkThumbprint.Compute(rsaParams);
        var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
        return new SigningKeySet(new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa });
    }

    /// <summary>
    /// Always reports "unchanged" so that <see cref="LoadKeysAsync"/> is invoked at most once for
    /// the lifetime of this service instance.
    /// </summary>
    /// <remarks>
    /// This is a hardcoded <see langword="false"/>, not a check against a memoized field, because
    /// the base class only ever calls this method once a previous <see cref="SigningKeySet"/>
    /// already exists — which itself implies <see cref="LoadKeysAsync"/> already ran successfully
    /// once. A conditional check here would be unreachable defensive code: there is no state in
    /// which this method is consulted before the first load has already happened. Dev keys are
    /// never rotated within a process lifetime (see the class-level remarks), so "unchanged" is
    /// always the correct answer once reached.
    /// </remarks>
    protected override ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken) => new(false);

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
