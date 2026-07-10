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
    // RefreshInterval doubles as the too-soon-NotBefore warning threshold (ADR 0011 §3.5) rather
    // than a re-download cadence — there is no external round trip to throttle here, since every
    // registered file lives on the local filesystem. The same one-minute floor still rejects a
    // value so short it would defeat the publish-then-activate protection against essentially any
    // real-world relying-party JWKS cache TTL.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, PemFileSigningOptions options)
    {
        var errors = new List<string>();

        if (options.RefreshInterval == TimeSpan.MaxValue)
        {
            errors.Add(
                "PemFileSigningOptions.RefreshInterval must be a positive, finite TimeSpan. " +
                "TimeSpan.MaxValue (the local-development provider's 'never refresh' value) cannot be " +
                "reused here.");
        }
        else if (options.RefreshInterval < MinimumRefreshInterval)
        {
            errors.Add(
                $"PemFileSigningOptions.RefreshInterval must be at least {MinimumRefreshInterval} " +
                "(it doubles as the too-soon-NotBefore warning threshold per ADR 0011 §3.5). You are " +
                "still responsible for ensuring RefreshInterval exceeds your actual relying parties' " +
                "JWKS cache TTL — this floor only rejects values that are almost certainly a mistake.");
        }

        if (string.IsNullOrWhiteSpace(options.Path))
            errors.Add("PemFileSigningOptions.Path must be set to a non-empty file path.");

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"PemFileSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        AppendDuplicatePathErrors(options, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    private static void AppendDuplicatePathErrors(PemFileSigningOptions options, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { options.Path };
        var hasEmptyAdditionalPath = false;
        var hasDuplicateAdditionalPath = false;

        foreach (var additional in options.AdditionalPaths)
        {
            if (string.IsNullOrWhiteSpace(additional))
                hasEmptyAdditionalPath = true;
            else if (!seen.Add(additional))
                hasDuplicateAdditionalPath = true;
        }

        if (hasEmptyAdditionalPath)
            errors.Add("AddFile was called with a null, empty, or whitespace-only path.");

        if (hasDuplicateAdditionalPath)
        {
            errors.Add(
                "AddFile was called with a path that duplicates the primary path or another " +
                "already-registered file.");
        }
    }
}
