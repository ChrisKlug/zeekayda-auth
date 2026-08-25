using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Validates <see cref="PfxFileSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddPfxFileSigning()</c> and activated by <c>ValidateOnStart()</c>.
/// </remarks>
internal sealed class PfxFileSigningOptionsValidator : IValidateOptions<PfxFileSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, PfxFileSigningOptions options)
    {
        var errors = new List<string>();

        if (options.Current is null)
        {
            errors.Add(
                "PfxFileSigningOptions.Current must be set to the PFX file that signs. Previous and " +
                "Next are optional; Current is not.");
        }

        AppendSlotErrors(nameof(PfxFileSigningOptions.Previous), options.Previous, errors);
        AppendSlotErrors(nameof(PfxFileSigningOptions.Current), options.Current, errors);
        AppendSlotErrors(nameof(PfxFileSigningOptions.Next), options.Next, errors);

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"PfxFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        AppendDuplicatePathErrors(options, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    private static void AppendSlotErrors(string slotName, PfxFile? slot, List<string> errors)
    {
        if (slot is null)
            return;

        if (string.IsNullOrWhiteSpace(slot.Path))
            errors.Add($"PfxFileSigningOptions.{slotName}.Path must be set to a non-empty file path.");

        // Every slot needs a password to be opened at all, including a published-only one, whose
        // certificate sits inside a password-protected safe.
        if (slot.PasswordSource is null)
            errors.Add($"PfxFileSigningOptions.{slotName}.PasswordSource must be set to a password-source delegate.");
    }

    private static void AppendDuplicatePathErrors(PfxFileSigningOptions options, List<string> errors) =>
        SigningFilePaths.AppendPathErrors(
            nameof(PfxFileSigningOptions),
            "Every configured path must be a distinct file.",
            errors,
            options.Previous?.Path,
            options.Current?.Path,
            options.Next?.Path);
}
