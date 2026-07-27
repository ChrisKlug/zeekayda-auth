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
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, WindowsCertificateStoreSigningOptions options)
    {
        var errors = new List<string>();

        if (KeySourcePublicationLeadValidator.ValidateMinimum(nameof(WindowsCertificateStoreSigningOptions), options.PublicationLead) is { } publicationLeadError)
            errors.Add(publicationLeadError);

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
        var hasEmptyAdditionalThumbprint = false;
        var hasDuplicateAdditionalThumbprint = false;
        foreach (var additional in options.AdditionalThumbprints)
        {
            // AddCertificate already normalizes its argument (ThumbprintFormat.Normalize), so a
            // thumbprint made up entirely of non-hex characters (e.g. copy-paste garbage) normalizes
            // to "" here rather than throwing at registration time. Left uncaught, it would only
            // surface later as a confusing "certificate not found: ''" configuration error at load
            // time instead of a clear validation failure.
            if (additional.Length == 0)
                hasEmptyAdditionalThumbprint = true;
            else if (!seen.Add(additional))
                hasDuplicateAdditionalThumbprint = true;
        }

        if (hasEmptyAdditionalThumbprint)
        {
            errors.Add(
                "AddCertificate was called with a thumbprint that contains no hex digits after " +
                "normalization. Verify the thumbprint was copied correctly.");
        }

        if (hasDuplicateAdditionalThumbprint)
        {
            errors.Add(
                "AddCertificate was called with a thumbprint that duplicates the primary or another " +
                "already-registered certificate.");
        }

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
