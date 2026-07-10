using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// Validates <see cref="MacOsKeychainSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddMacOsKeychainSigning()</c> and activated by <c>ValidateOnStart()</c>. This
/// validator only checks facts derivable from the options shape itself — whether a given label turns
/// out to be certificate-backed or a bare key is only knowable once the Keychain is actually queried,
/// so the bare-key-without-activation fail-fast rule (issue #290 AC #13) lives in
/// <see cref="MacOsKeychainSigningJwtSigningService.LoadKeysAsync"/> instead, alongside the rest of
/// the load-time rotation logic.
/// </remarks>
internal sealed class MacOsKeychainSigningOptionsValidator : IValidateOptions<MacOsKeychainSigningOptions>
{
    // RefreshInterval doubles as the too-soon-activation warning threshold (ADR 0011 §3.5) rather
    // than a re-download cadence — there is no external round trip to throttle here, since every
    // registered label lives in the local Keychain. The same one-minute floor as the Windows
    // Certificate Store provider rejects a value so short it would defeat the publish-then-activate
    // protection against essentially any real-world relying-party JWKS cache TTL.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, MacOsKeychainSigningOptions options)
    {
        var errors = new List<string>();

        if (options.RefreshInterval == TimeSpan.MaxValue)
        {
            errors.Add(
                "MacOsKeychainSigningOptions.RefreshInterval must be a positive, finite TimeSpan. " +
                "TimeSpan.MaxValue (the local-development provider's 'never refresh' value) cannot " +
                "be reused here.");
        }
        else if (options.RefreshInterval < MinimumRefreshInterval)
        {
            errors.Add(
                $"MacOsKeychainSigningOptions.RefreshInterval must be at least {MinimumRefreshInterval} " +
                "(it doubles as the too-soon-activation warning threshold per ADR 0011 §3.5). You are " +
                "still responsible for ensuring RefreshInterval exceeds your actual relying parties' " +
                "JWKS cache TTL — this floor only rejects values that are almost certainly a mistake.");
        }

        if (string.IsNullOrWhiteSpace(options.Label))
            errors.Add("MacOsKeychainSigningOptions.Label must be set to a non-empty Keychain item label.");

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"MacOsKeychainSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        AddDuplicateLabelErrors(options, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    private static void AddDuplicateLabelErrors(MacOsKeychainSigningOptions options, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { options.Label };
        var hasDuplicate = false;

        foreach (var additional in options.AdditionalKeys)
        {
            if (!seen.Add(additional.Label))
                hasDuplicate = true;
        }

        if (hasDuplicate)
        {
            errors.Add(
                "AddKey was called with a label that duplicates the primary label or another " +
                "already-registered label.");
        }
    }
}
