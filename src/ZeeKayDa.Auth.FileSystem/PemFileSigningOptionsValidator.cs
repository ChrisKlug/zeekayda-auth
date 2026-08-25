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
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, PemFileSigningOptions options)
    {
        var errors = new List<string>();

        if (options.Current is null)
        {
            errors.Add(
                "PemFileSigningOptions.Current must be set to the PEM file that signs. Previous and " +
                "Next are optional; Current is not.");
        }

        AppendPathError(nameof(PemFileSigningOptions.Previous), options.Previous?.Path, errors);
        AppendPathError(nameof(PemFileSigningOptions.Current), options.Current?.Path, errors);
        AppendPathError(nameof(PemFileSigningOptions.Next), options.Next?.Path, errors);
        AppendCurrentKeyPathError(options.Current, errors);

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"PemFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        AppendDuplicatePathErrors(options, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    // Previous and Next are PemCertificateFile, which has no KeyPath to check — only Current can
    // name a private key at all, which is why there is no "a published-only slot named a key file"
    // error to report here.
    private static void AppendPathError(string slotName, string? path, List<string> errors)
    {
        if (path is not null && string.IsNullOrWhiteSpace(path))
            errors.Add($"PemFileSigningOptions.{slotName}.Path must be set to a non-empty file path.");
    }

    private static void AppendCurrentKeyPathError(PemSigningFile? current, List<string> errors)
    {
        if (current?.KeyPath is { } keyPath && string.IsNullOrWhiteSpace(keyPath))
        {
            errors.Add(
                "PemFileSigningOptions.Current.KeyPath must be null (a combined cert+key Path) or a " +
                "non-empty file path — never empty/whitespace-only.");
        }
    }

    // Every filesystem path this configuration touches must be pairwise distinct — two slots sharing
    // a path would publish one key twice under two slot names, or make the same file both the
    // outgoing and the incoming key of a rotation. Each non-empty path is normalized via
    // Path.GetFullPath before comparison, so differences like "tls.pem" vs "./tls.pem" are still
    // caught. That call is pure string canonicalization only for a rooted path; for a relative one it
    // reads the current directory, which is why the catch below covers I/O failures too. Symlink
    // resolution and case-insensitive-filesystem comparison are deliberately out of scope: this
    // degrades to a load failure or a duplicate-kid rejection in SigningKeySetBuilder, not key
    // confusion, if two paths are equivalent but not caught here.
    private static void AppendDuplicatePathErrors(PemFileSigningOptions options, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var hasDuplicatePath = false;
        var hasUncanonicalizablePath = false;

        // Empty/whitespace-only paths are already reported by AppendSlotErrors, so they are skipped
        // here rather than re-flagged; they still must not be added to `seen`, since two
        // independently-empty values are not "the same path".
        void Track(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or IOException)
            {
                // GetFullPath throws on an embedded NUL or a path over the platform limit, and — for a
                // relative path, since it resolves against the current directory — on an I/O failure
                // reading that directory. All of them are configuration errors like any other and
                // belong in the aggregated result, not thrown out of Validate where they would escape
                // as something other than an options failure. DirectoryNotFoundException derives from
                // IOException, so a deleted working directory is covered.
                hasUncanonicalizablePath = true;
                return;
            }

            if (!seen.Add(fullPath))
                hasDuplicatePath = true;
        }

        Track(options.Previous?.Path);
        Track(options.Current?.Path);
        Track(options.Current?.KeyPath);
        Track(options.Next?.Path);

        if (hasUncanonicalizablePath)
        {
            errors.Add(
                "A PemFileSigningOptions slot names a path the operating system cannot resolve — it " +
                "contains an invalid character (such as an embedded NUL) or exceeds the platform's " +
                "maximum path length.");
        }

        if (hasDuplicatePath)
        {
            errors.Add(
                "Two PemFileSigningOptions slots reference the same file. Every Path, and Current's " +
                "KeyPath, must be a distinct file.");
        }
    }
}
