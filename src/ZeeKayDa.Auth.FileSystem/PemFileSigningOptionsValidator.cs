using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Validates <see cref="PemFileSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddPemFileSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class PemFileSigningOptionsValidator : ZeeKayDaOptionsValidator<PemFileSigningOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(
        string? name,
        PemFileSigningOptions options)
    {
        if (options.Files.Count == 0)
        {
            yield return new(
                "configuration.pem_file_signing.files.empty",
                "PemFileSigningOptions.Files must list at least one PEM file.");
        }

        for (var i = 0; i < options.Files.Count; i++)
        {
            foreach (var failure in FileFailures(i, options.Files[i]))
                yield return failure;
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            yield return new(
                "configuration.pem_file_signing.algorithm.undefined_value",
                $"PemFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        var paths = options.Files.Where(f => f is not null).SelectMany(f => new[] { f.Path, f.KeyPath }).ToArray();
        foreach (var failure in SigningFilePaths.PathFailures(
            nameof(PemFileSigningOptions),
            "configuration.pem_file_signing.paths",
            "Every Path and KeyPath must be a distinct file.",
            paths))
        {
            yield return failure;
        }
    }

    // A null Path means a caller suppressed the record's non-nullable annotation; it is reported like
    // any other unusable path rather than left to fail confusingly further in.
    private static IEnumerable<ZeeKayDaConfigurationFailure> FileFailures(int index, PemSigningFile? file)
    {
        if (file is null)
        {
            yield return new(
                "configuration.pem_file_signing.files.null_entry",
                $"PemFileSigningOptions.Files[{index}] is null.");
            yield break;
        }

        if (string.IsNullOrWhiteSpace(file.Path))
        {
            yield return new(
                "configuration.pem_file_signing.files.path.missing",
                $"PemFileSigningOptions.Files[{index}].Path must be set to a non-empty file path.");
        }

        if (file.KeyPath is { } keyPath && string.IsNullOrWhiteSpace(keyPath))
        {
            yield return new(
                "configuration.pem_file_signing.files.key_path.blank",
                $"PemFileSigningOptions.Files[{index}].KeyPath must be null (a combined cert+key Path) or a " +
                "non-empty file path — never empty/whitespace-only.");
        }
    }
}
