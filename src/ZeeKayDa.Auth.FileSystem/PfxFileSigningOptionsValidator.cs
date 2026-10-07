using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Validates <see cref="PfxFileSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddPfxFileSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class PfxFileSigningOptionsValidator : ZeeKayDaOptionsValidator<PfxFileSigningOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(
        string? name,
        PfxFileSigningOptions options)
    {
        if (options.Files.Count == 0)
        {
            yield return new(
                "configuration.pfx_file_signing.files.empty",
                "PfxFileSigningOptions.Files must list at least one PFX file.");
        }

        for (var i = 0; i < options.Files.Count; i++)
        {
            foreach (var failure in FileFailures(i, options.Files[i]))
                yield return failure;
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            yield return new(
                "configuration.pfx_file_signing.algorithm.undefined_value",
                $"PfxFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        var paths = options.Files.Where(f => f is not null).Select(f => f.Path).ToArray();
        foreach (var failure in SigningFilePaths.PathFailures(
            nameof(PfxFileSigningOptions),
            "configuration.pfx_file_signing.paths",
            "Every listed path must be a distinct file.",
            paths))
        {
            yield return failure;
        }
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> FileFailures(int index, PfxFile? file)
    {
        if (file is null)
        {
            yield return new(
                "configuration.pfx_file_signing.files.null_entry",
                $"PfxFileSigningOptions.Files[{index}] is null.");
            yield break;
        }

        if (string.IsNullOrWhiteSpace(file.Path))
        {
            yield return new(
                "configuration.pfx_file_signing.files.path.missing",
                $"PfxFileSigningOptions.Files[{index}].Path must be set to a non-empty file path.");
        }

        if (file.PasswordSource is null)
        {
            yield return new(
                "configuration.pfx_file_signing.files.password_source.missing",
                $"PfxFileSigningOptions.Files[{index}].PasswordSource must be set to a password-source delegate.");
        }
    }
}
