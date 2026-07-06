using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Validates <see cref="WindowsCertificateStoreSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddWindowsCertificateStoreSigning()</c> and activated by <c>ValidateOnStart()</c>.
/// </remarks>
internal sealed class WindowsCertificateStoreSigningOptionsValidator : IValidateOptions<WindowsCertificateStoreSigningOptions>
{
    // RefreshInterval doubles as the too-soon-NotBefore warning threshold (ADR 0011 §3.5) rather
    // than a re-download cadence — there is no external round trip to throttle here, since every
    // registered certificate lives in the local store. The same one-minute floor still rejects a
    // value so short it would defeat the publish-then-activate protection against essentially any
    // real-world relying-party JWKS cache TTL.
    private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, WindowsCertificateStoreSigningOptions options)
    {
        var errors = new List<string>();

        if (options.RefreshInterval == TimeSpan.MaxValue)
        {
            errors.Add(
                "WindowsCertificateStoreSigningOptions.RefreshInterval must be a positive, finite " +
                "TimeSpan. TimeSpan.MaxValue (the local-development provider's 'never refresh' value) " +
                "cannot be reused here.");
        }
        else if (options.RefreshInterval < MinimumRefreshInterval)
        {
            errors.Add(
                $"WindowsCertificateStoreSigningOptions.RefreshInterval must be at least {MinimumRefreshInterval} " +
                "(it doubles as the too-soon-NotBefore warning threshold per ADR 0011 §3.5). You are still " +
                "responsible for ensuring RefreshInterval exceeds your actual relying parties' JWKS cache " +
                "TTL — this floor only rejects values that are almost certainly a mistake.");
        }

        if (string.IsNullOrWhiteSpace(options.Thumbprint))
        {
            errors.Add(
                "WindowsCertificateStoreSigningOptions.Thumbprint must be set to a non-empty certificate thumbprint.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"WindowsCertificateStoreSigningOptions.Algorithm value '{options.Algorithm}' is not a defined " +
                $"{nameof(SigningAlgorithm)} member.");
        }

        var normalizedPrimary = ThumbprintFormat.Normalize(options.Thumbprint);
        var seen = new HashSet<string>(StringComparer.Ordinal) { normalizedPrimary };
        foreach (var additional in options.AdditionalThumbprints)
        {
            if (!seen.Add(additional))
            {
                errors.Add(
                    "AddCertificate was called with a thumbprint that duplicates the primary or another " +
                    "already-registered certificate.");
                break;
            }
        }

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
