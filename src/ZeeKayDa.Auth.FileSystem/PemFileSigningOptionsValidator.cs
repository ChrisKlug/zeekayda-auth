using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Validates <see cref="PemFileSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddPemFileSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class PemFileSigningOptionsValidator : IValidateOptions<PemFileSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, PemFileSigningOptions options)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();

        if (options.Current is null)
        {
            failures.Add(new(
                "configuration.pem_file_signing.current.missing",
                "PemFileSigningOptions.Current must be set to the PEM file that signs. Previous and " +
                "Next are optional; Current is not."));
        }

        AppendPathError(nameof(PemFileSigningOptions.Previous), options.Previous is not null, options.Previous?.Path, failures);
        AppendPathError(nameof(PemFileSigningOptions.Current), options.Current is not null, options.Current?.Path, failures);
        AppendPathError(nameof(PemFileSigningOptions.Next), options.Next is not null, options.Next?.Path, failures);
        AppendCurrentKeyPathError(options.Current, failures);

        if (!Enum.IsDefined(options.Algorithm))
        {
            failures.Add(new(
                "configuration.pem_file_signing.algorithm.undefined_value",
                $"PemFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member."));
        }

        AppendDuplicatePathErrors(options, failures);

        return failures.ThrowIfAny();
    }

    // Previous and Next are PemCertificateFile, which has no KeyPath to check — only Current can
    // name a private key at all, which is why there is no "a published-only slot named a key file"
    // error to report here. A configured slot whose Path is null is reported like any other unusable
    // path rather than skipped: the record's Path is non-nullable, so reaching here with null means a
    // caller suppressed that, and silence would turn it into a confusing failure further in.
    private static void AppendPathError(string slotName, bool slotConfigured, string? path, List<ZeeKayDaConfigurationFailure> failures)
    {
        if (slotConfigured && string.IsNullOrWhiteSpace(path))
            failures.Add(new(
                $"configuration.pem_file_signing.{slotName.ToLowerInvariant()}.path.missing",
                $"PemFileSigningOptions.{slotName}.Path must be set to a non-empty file path."));
    }

    private static void AppendCurrentKeyPathError(PemSigningFile? current, List<ZeeKayDaConfigurationFailure> failures)
    {
        if (current?.KeyPath is { } keyPath && string.IsNullOrWhiteSpace(keyPath))
        {
            failures.Add(new(
                "configuration.pem_file_signing.current.key_path.blank",
                "PemFileSigningOptions.Current.KeyPath must be null (a combined cert+key Path) or a " +
                "non-empty file path — never empty/whitespace-only."));
        }
    }

    private static void AppendDuplicatePathErrors(PemFileSigningOptions options, List<ZeeKayDaConfigurationFailure> failures) =>
        SigningFilePaths.AppendPathErrors(
            nameof(PemFileSigningOptions),
            "configuration.pem_file_signing.paths",
            "Every Path, and Current's KeyPath, must be a distinct file.",
            failures,
            options.Previous?.Path,
            options.Current?.Path,
            options.Current?.KeyPath,
            options.Next?.Path);
}
