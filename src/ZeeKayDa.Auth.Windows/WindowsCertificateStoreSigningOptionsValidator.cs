using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>Validates <see cref="WindowsCertificateStoreSigningOptions"/> at startup.</summary>
internal sealed class WindowsCertificateStoreSigningOptionsValidator : ZeeKayDaOptionsValidator<WindowsCertificateStoreSigningOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(
        string? name,
        WindowsCertificateStoreSigningOptions options)
    {
        if (options.Certificates.Count == 0)
        {
            yield return new(
                "configuration.windows_certificate_store_signing.certificates.empty",
                $"{nameof(WindowsCertificateStoreSigningOptions)}.{nameof(WindowsCertificateStoreSigningOptions.Certificates)} " +
                "must list at least one certificate.");
        }

        for (var i = 0; i < options.Certificates.Count; i++)
        {
            if (options.Certificates[i] is null)
            {
                yield return new(
                    "configuration.windows_certificate_store_signing.certificates.null_entry",
                    $"{nameof(WindowsCertificateStoreSigningOptions)}.{nameof(WindowsCertificateStoreSigningOptions.Certificates)}[{i}] is null.");
            }
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            yield return new(
                "configuration.windows_certificate_store_signing.algorithm.undefined_value",
                $"{nameof(WindowsCertificateStoreSigningOptions)}.{nameof(WindowsCertificateStoreSigningOptions.Algorithm)} " +
                $"value '{options.Algorithm}' is not a defined {nameof(SigningAlgorithm)} member.");
        }

        foreach (var failure in FindDuplicates(options))
            yield return failure;
    }

    /// <summary>Reports every certificate listed more than once, which would list one key twice under one source id.</summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> FindDuplicates(WindowsCertificateStoreSigningOptions options) =>
        options.Certificates
            .Where(lookup => lookup is not null)
            .GroupBy(lookup => lookup)
            .Where(group => group.Count() > 1)
            .Select(group => new ZeeKayDaConfigurationFailure(
                "configuration.windows_certificate_store_signing.certificates.duplicate",
                $"Certificate '{group.Key.NormalizedThumbprint}' is listed {group.Count()} times. Each " +
                "certificate must be listed once."));
}
