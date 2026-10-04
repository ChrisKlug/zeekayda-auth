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
        if (options.Current is null)
        {
            yield return new(
                "configuration.pem_file_signing.current.missing",
                "PemFileSigningOptions.Current must be set to the PEM file that signs. Previous and " +
                "Next are optional; Current is not.");
        }

        var slotFailures = PathFailure(nameof(PemFileSigningOptions.Previous), options.Previous is not null, options.Previous?.Path)
            .Concat(PathFailure(nameof(PemFileSigningOptions.Current), options.Current is not null, options.Current?.Path))
            .Concat(PathFailure(nameof(PemFileSigningOptions.Next), options.Next is not null, options.Next?.Path))
            .Concat(CurrentKeyPathFailure(options.Current));
        foreach (var failure in slotFailures)
            yield return failure;

        if (!Enum.IsDefined(options.Algorithm))
        {
            yield return new(
                "configuration.pem_file_signing.algorithm.undefined_value",
                $"PemFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        foreach (var failure in DuplicatePathFailures(options))
            yield return failure;
    }

    // Previous and Next are PemCertificateFile, which has no KeyPath to check — only Current can
    // name a private key at all, which is why there is no "a published-only slot named a key file"
    // error to report here. A configured slot whose Path is null is reported like any other unusable
    // path rather than skipped: the record's Path is non-nullable, so reaching here with null means a
    // caller suppressed that, and silence would turn it into a confusing failure further in.
    private static IEnumerable<ZeeKayDaConfigurationFailure> PathFailure(string slotName, bool slotConfigured, string? path)
    {
        if (slotConfigured && string.IsNullOrWhiteSpace(path))
            yield return new(
                $"configuration.pem_file_signing.{slotName.ToLowerInvariant()}.path.missing",
                $"PemFileSigningOptions.{slotName}.Path must be set to a non-empty file path.");
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> CurrentKeyPathFailure(PemSigningFile? current)
    {
        if (current?.KeyPath is { } keyPath && string.IsNullOrWhiteSpace(keyPath))
        {
            yield return new(
                "configuration.pem_file_signing.current.key_path.blank",
                "PemFileSigningOptions.Current.KeyPath must be null (a combined cert+key Path) or a " +
                "non-empty file path — never empty/whitespace-only.");
        }
    }

    private static List<ZeeKayDaConfigurationFailure> DuplicatePathFailures(PemFileSigningOptions options) =>
        SigningFilePaths.PathFailures(
            nameof(PemFileSigningOptions),
            "configuration.pem_file_signing.paths",
            "Every Path, and Current's KeyPath, must be a distinct file.",
            options.Previous?.Path,
            options.Current?.Path,
            options.Current?.KeyPath,
            options.Next?.Path);
}
