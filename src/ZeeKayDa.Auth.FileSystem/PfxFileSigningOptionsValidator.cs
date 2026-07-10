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
    // See PemFileSigningOptionsValidator for why this floor exists and why it is not a re-download
    // cadence in this provider.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, PfxFileSigningOptions options)
    {
        var errors = new List<string>();

        if (options.RefreshInterval == TimeSpan.MaxValue)
        {
            errors.Add(
                "PfxFileSigningOptions.RefreshInterval must be a positive, finite TimeSpan. " +
                "TimeSpan.MaxValue (the local-development provider's 'never refresh' value) cannot be " +
                "reused here.");
        }
        else if (options.RefreshInterval < MinimumRefreshInterval)
        {
            errors.Add(
                $"PfxFileSigningOptions.RefreshInterval must be at least {MinimumRefreshInterval} " +
                "(it doubles as the too-soon-NotBefore warning threshold per ADR 0011 §3.5). You are " +
                "still responsible for ensuring RefreshInterval exceeds your actual relying parties' " +
                "JWKS cache TTL — this floor only rejects values that are almost certainly a mistake.");
        }

        if (string.IsNullOrWhiteSpace(options.Path))
            errors.Add("PfxFileSigningOptions.Path must be set to a non-empty file path.");

        if (options.PasswordSource is null)
        {
            errors.Add(
                "PfxFileSigningOptions.PasswordSource must be set. AddPfxFileSigning requires a " +
                "password-source delegate for the primary file.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"PfxFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        AppendAdditionalFileErrors(options, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    private static void AppendAdditionalFileErrors(PfxFileSigningOptions options, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { options.Path };
        var hasEmptyAdditionalPath = false;
        var hasDuplicateAdditionalPath = false;
        var hasMissingPasswordSource = false;

        foreach (var file in options.AdditionalFiles)
        {
            if (string.IsNullOrWhiteSpace(file.Path))
                hasEmptyAdditionalPath = true;
            else if (!seen.Add(file.Path))
                hasDuplicateAdditionalPath = true;

            if (file.PasswordSource is null)
                hasMissingPasswordSource = true;
        }

        if (hasEmptyAdditionalPath)
            errors.Add("AddFile was called with a null, empty, or whitespace-only path.");

        if (hasDuplicateAdditionalPath)
        {
            errors.Add(
                "AddFile was called with a path that duplicates the primary path or another " +
                "already-registered file.");
        }

        if (hasMissingPasswordSource)
            errors.Add("AddFile was called with a null password-source delegate.");
    }
}
