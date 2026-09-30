using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Validates <see cref="PfxFileSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddPfxFileSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class PfxFileSigningOptionsValidator : IValidateOptions<PfxFileSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, PfxFileSigningOptions options)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();

        if (options.Current is null)
        {
            failures.Add(new(
                "configuration.pfx_file_signing.current.missing",
                "PfxFileSigningOptions.Current must be set to the PFX file that signs. Previous and " +
                "Next are optional; Current is not."));
        }

        AppendSlotErrors(nameof(PfxFileSigningOptions.Previous), options.Previous, failures);
        AppendSlotErrors(nameof(PfxFileSigningOptions.Current), options.Current, failures);
        AppendSlotErrors(nameof(PfxFileSigningOptions.Next), options.Next, failures);

        if (!Enum.IsDefined(options.Algorithm))
        {
            failures.Add(new(
                "configuration.pfx_file_signing.algorithm.undefined_value",
                $"PfxFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member."));
        }

        AppendDuplicatePathErrors(options, failures);

        return failures.ThrowIfAny();
    }

    private static void AppendSlotErrors(string slotName, PfxFile? slot, List<ZeeKayDaConfigurationFailure> failures)
    {
        if (slot is null)
            return;

        if (string.IsNullOrWhiteSpace(slot.Path))
            failures.Add(new(
                $"configuration.pfx_file_signing.{slotName.ToLowerInvariant()}.path.missing",
                $"PfxFileSigningOptions.{slotName}.Path must be set to a non-empty file path."));

        // Every slot needs a password to be opened at all, including a published-only one, whose
        // certificate sits inside a password-protected safe.
        if (slot.PasswordSource is null)
            failures.Add(new(
                $"configuration.pfx_file_signing.{slotName.ToLowerInvariant()}.password_source.missing",
                $"PfxFileSigningOptions.{slotName}.PasswordSource must be set to a password-source delegate."));
    }

    private static void AppendDuplicatePathErrors(PfxFileSigningOptions options, List<ZeeKayDaConfigurationFailure> failures) =>
        SigningFilePaths.AppendPathErrors(
            nameof(PfxFileSigningOptions),
            "configuration.pfx_file_signing.paths",
            "Every configured path must be a distinct file.",
            failures,
            options.Previous?.Path,
            options.Current?.Path,
            options.Next?.Path);
}
