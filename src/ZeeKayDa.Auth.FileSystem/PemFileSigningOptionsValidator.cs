using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Validates <see cref="PemFileSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddPemFileSigning()</c> and activated by <c>ValidateOnStart()</c>.
/// </remarks>
internal sealed class PemFileSigningOptionsValidator : IValidateOptions<PemFileSigningOptions>
{
    // KeySourceRefreshInterval doubles as the too-soon-NotBefore warning threshold (ADR 0011 §3.5) rather
    // than a re-download cadence — there is no external round trip to throttle here, since every
    // registered file lives on the local filesystem. The same one-minute floor still rejects a
    // value so short it would defeat the publish-then-activate protection against essentially any
    // real-world relying-party JWKS cache TTL.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, PemFileSigningOptions options)
    {
        var errors = new List<string>();

        if (options.KeySourceRefreshInterval is null)
        {
            errors.Add(
                "PemFileSigningOptions.KeySourceRefreshInterval must be a positive, finite TimeSpan. " +
                "null (the local-development provider's 'load once, never reload' static mode) cannot " +
                "be reused here.");
        }
        else if (options.KeySourceRefreshInterval.Value < MinimumRefreshInterval)
        {
            errors.Add(
                $"PemFileSigningOptions.KeySourceRefreshInterval must be at least {MinimumRefreshInterval} " +
                "(it doubles as the too-soon-NotBefore warning threshold per ADR 0011 §3.5). You are " +
                "still responsible for ensuring KeySourceRefreshInterval exceeds your actual relying parties' " +
                "JWKS cache TTL — this floor only rejects values that are almost certainly a mistake.");
        }

        if (string.IsNullOrWhiteSpace(options.Path))
            errors.Add("PemFileSigningOptions.Path must be set to a non-empty file path.");

        if (options.KeyPath is not null && string.IsNullOrWhiteSpace(options.KeyPath))
        {
            errors.Add(
                "PemFileSigningOptions.KeyPath must be null (a combined cert+key Path) or a " +
                "non-empty file path — never empty/whitespace-only.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"PemFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        AppendDuplicatePathErrors(options, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    // Every filesystem path this configuration touches — the primary cert path, its optional
    // companion key path, and each additional file's cert/key paths — must be pairwise distinct.
    // Two entries sharing a path would make FileSigningJwtSigningService<TOptions>'s flattened
    // path-timestamp tracking ambiguous (issue #405): the same path would back two different
    // registered entries, so a single stat/mtime cannot unambiguously represent "this entry
    // changed" for both.
    //
    // Each non-empty path is normalized via Path.GetFullPath before comparison, so purely
    // string-level differences (e.g. "tls.pem" vs "./tls.pem", or redundant separators like
    // "/etc/zeekayda//tls.pem" vs "/etc/zeekayda/tls.pem") are still caught as duplicates. This
    // is pure string canonicalization — no filesystem access. It deliberately does NOT resolve
    // symlink targets or perform case-insensitive-filesystem comparison; that would require
    // filesystem I/O inside an options validator and platform-dependent guessing, which was
    // assessed in PR #411's security review as disproportionate to a non-exploitable
    // correctness gap (it degrades to a load failure, not key confusion).
    private static void AppendDuplicatePathErrors(PemFileSigningOptions options, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var hasEmptyAdditionalPath = false;
        var hasDuplicatePath = false;

        // Empty/whitespace-only Path/KeyPath is already reported by the dedicated errors above, so
        // an empty value here is silently skipped rather than re-flagged via hasEmptyAdditionalPath
        // (which is reserved for AddFile's own empty-path error message below); it still must not be
        // added to `seen`, since two independently-empty values are not "the same path".
        void Track(string? path, bool reportEmptyAsAddFileError)
        {
            if (path is null)
                return;

            if (string.IsNullOrWhiteSpace(path))
            {
                if (reportEmptyAsAddFileError)
                    hasEmptyAdditionalPath = true;
            }
            else if (!seen.Add(Path.GetFullPath(path)))
            {
                hasDuplicatePath = true;
            }
        }

        Track(options.Path, reportEmptyAsAddFileError: false);
        Track(options.KeyPath, reportEmptyAsAddFileError: false);

        foreach (var file in options.AdditionalFiles)
        {
            Track(file.Path, reportEmptyAsAddFileError: true);
            Track(file.KeyPath, reportEmptyAsAddFileError: true);
        }

        if (hasEmptyAdditionalPath)
            errors.Add("AddFile was called with a null, empty, or whitespace-only path.");

        if (hasDuplicatePath)
        {
            errors.Add(
                "AddFile was called with a path that duplicates the primary path, the primary key " +
                "path, or another already-registered file's path/key path.");
        }
    }
}
