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

        AppendSlotErrors(nameof(PemFileSigningOptions.Previous), options.Previous, errors);
        AppendSlotErrors(nameof(PemFileSigningOptions.Current), options.Current, errors);
        AppendSlotErrors(nameof(PemFileSigningOptions.Next), options.Next, errors);

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"PemFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        AppendDuplicatePathErrors(options, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    private static void AppendSlotErrors(string slotName, PemSigningFile? slot, List<string> errors)
    {
        if (slot is null)
            return;

        if (string.IsNullOrWhiteSpace(slot.Path))
            errors.Add($"PemFileSigningOptions.{slotName}.Path must be set to a non-empty file path.");

        if (slot.KeyPath is not null && string.IsNullOrWhiteSpace(slot.KeyPath))
        {
            errors.Add(
                $"PemFileSigningOptions.{slotName}.KeyPath must be null (a combined cert+key Path) " +
                "or a non-empty file path — never empty/whitespace-only.");
        }
    }

    // Every filesystem path this configuration touches must be pairwise distinct — two slots sharing
    // a path would publish one key twice under two slot names, or make the same file both the
    // outgoing and the incoming key of a rotation. Each non-empty path is normalized via
    // Path.GetFullPath before comparison (pure string canonicalization, no filesystem access), so
    // differences like "tls.pem" vs "./tls.pem" are still caught. Symlink resolution and
    // case-insensitive-filesystem comparison are deliberately out of scope: this degrades to a load
    // failure or a duplicate-kid rejection in SigningKeySetBuilder, not key confusion, if two paths
    // are equivalent but not caught here.
    private static void AppendDuplicatePathErrors(PemFileSigningOptions options, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var hasDuplicatePath = false;

        // Empty/whitespace-only paths are already reported by AppendSlotErrors, so they are skipped
        // here rather than re-flagged; they still must not be added to `seen`, since two
        // independently-empty values are not "the same path".
        void Track(string? path)
        {
            if (!string.IsNullOrWhiteSpace(path) && !seen.Add(Path.GetFullPath(path)))
                hasDuplicatePath = true;
        }

        foreach (var slot in new[] { options.Previous, options.Current, options.Next })
        {
            Track(slot?.Path);
            Track(slot?.KeyPath);
        }

        if (hasDuplicatePath)
        {
            errors.Add(
                "Two PemFileSigningOptions slots reference the same file. Every Path and KeyPath " +
                "across Previous, Current, and Next must be a distinct file.");
        }
    }
}
