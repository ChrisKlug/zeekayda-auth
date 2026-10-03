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
        if (options.Current is null)
        {
            yield return new(
                "configuration.pfx_file_signing.current.missing",
                "PfxFileSigningOptions.Current must be set to the PFX file that signs. Previous and " +
                "Next are optional; Current is not.");
        }

        var slotFailures = SlotFailures(nameof(PfxFileSigningOptions.Previous), options.Previous)
            .Concat(SlotFailures(nameof(PfxFileSigningOptions.Current), options.Current))
            .Concat(SlotFailures(nameof(PfxFileSigningOptions.Next), options.Next));
        foreach (var failure in slotFailures)
            yield return failure;

        if (!Enum.IsDefined(options.Algorithm))
        {
            yield return new(
                "configuration.pfx_file_signing.algorithm.undefined_value",
                $"PfxFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        foreach (var failure in DuplicatePathFailures(options))
            yield return failure;
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> SlotFailures(string slotName, PfxFile? slot)
    {
        if (slot is null)
            yield break;

        if (string.IsNullOrWhiteSpace(slot.Path))
            yield return new(
                $"configuration.pfx_file_signing.{slotName.ToLowerInvariant()}.path.missing",
                $"PfxFileSigningOptions.{slotName}.Path must be set to a non-empty file path.");

        // Every slot needs a password to be opened at all, including a published-only one, whose
        // certificate sits inside a password-protected safe.
        if (slot.PasswordSource is null)
            yield return new(
                $"configuration.pfx_file_signing.{slotName.ToLowerInvariant()}.password_source.missing",
                $"PfxFileSigningOptions.{slotName}.PasswordSource must be set to a password-source delegate.");
    }

    private static List<ZeeKayDaConfigurationFailure> DuplicatePathFailures(PfxFileSigningOptions options) =>
        SigningFilePaths.PathFailures(
            nameof(PfxFileSigningOptions),
            "configuration.pfx_file_signing.paths",
            "Every configured path must be a distinct file.",
            options.Previous?.Path,
            options.Current?.Path,
            options.Next?.Path);
}
