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

    private static void AppendDuplicatePathErrors(PemFileSigningOptions options, List<string> errors)
    {
        var paths = new SigningFilePathSet();

        paths.Track(options.Previous?.Path);
        paths.Track(options.Current?.Path);
        paths.Track(options.Current?.KeyPath);
        paths.Track(options.Next?.Path);

        paths.AppendErrors(nameof(PemFileSigningOptions), errors);
    }
}
