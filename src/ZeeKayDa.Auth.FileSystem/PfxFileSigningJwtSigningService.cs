using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more PFX/PKCS#12 bundles from the filesystem
/// and signs locally, in process, using each certificate's private-key handle.
/// </summary>
internal sealed class PfxFileSigningJwtSigningService : FileSigningJwtSigningService<PfxFileSigningOptions>
{
    private readonly FileSigningKeyReader _reader;

    public PfxFileSigningJwtSigningService(
        IOptions<PfxFileSigningOptions> options,
        TimeProvider timeProvider,
        FileSigningKeyReader reader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(reader);
        _reader = reader;
    }

    /// <inheritdoc/>
    protected override IReadOnlyList<RegisteredSigningFile> GetRegisteredFiles(PfxFileSigningOptions options)
    {
        // The PFX format inherently bundles cert+key+chain in one file, so every entry here has only
        // a single backing path — issue #405's optional companion key path is PEM-only and does not
        // apply to this provider.
        var files = new List<RegisteredSigningFile>(1 + options.AdditionalFiles.Count) { new(options.Path) };
        files.AddRange(options.AdditionalFiles.Select(file => new RegisteredSigningFile(file.Path)));
        return files;
    }

    /// <inheritdoc/>
    protected override async ValueTask<X509Certificate2> LoadCertificateAsync(
        RegisteredSigningFile file, PfxFileSigningOptions options, CancellationToken cancellationToken)
    {
        var path = file.Id;
        var passwordSource = ResolvePasswordSource(path, options);
        var bytes = await _reader.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var password = await passwordSource(cancellationToken).ConfigureAwait(false);

        try
        {
            return X509CertificateLoader.LoadPkcs12(bytes, password);
        }
        catch (CryptographicException ex)
        {
            // ex.Message comes from the BCL PKCS#12 parser and never echoes the supplied password —
            // still, the message is not further embellished with any secret-derived detail here.
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pfx",
                $"The PFX/PKCS#12 file at '{path}' could not be loaded: {ex.Message}. Verify the file " +
                "is a valid PKCS#12 bundle and that the configured password is correct."));
        }
    }

    /// <inheritdoc/>
    protected override SigningAlgorithm GetAlgorithm(PfxFileSigningOptions options) => options.Algorithm;

    private static Func<CancellationToken, ValueTask<string>> ResolvePasswordSource(string path, PfxFileSigningOptions options)
    {
        if (string.Equals(path, options.Path, StringComparison.Ordinal))
            return options.PasswordSource!;

        var match = options.AdditionalFiles.FirstOrDefault(file => string.Equals(file.Path, path, StringComparison.Ordinal));

        // Unreachable in practice: `path` always comes from GetRegisteredPaths(options) (this
        // provider's own primary Path plus every AdditionalFiles entry), and
        // PfxFileSigningOptionsValidator rejects a null PasswordSource on both the primary and every
        // AddFile-registered entry before startup completes. InvalidOperationException (not
        // ZeeKayDaConfigurationException) is deliberate here — this guards an internal invariant that
        // "can't happen" given the two callers above, not a user-facing configuration failure a
        // relying operator could hit and needs to act on.
        return match.PasswordSource
            ?? throw new InvalidOperationException($"No password source is registered for path '{path}'.");
    }
}
