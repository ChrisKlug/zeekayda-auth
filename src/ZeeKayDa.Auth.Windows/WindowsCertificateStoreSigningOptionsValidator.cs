using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Validates <see cref="WindowsCertificateStoreSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddWindowsCertificateStoreSigning()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// There is no empty-thumbprint check here: <see cref="CertificateLookup.ByThumbprint"/> rejects a
/// thumbprint with no hex digits at construction, so a configured slot always holds a usable one.
/// </remarks>
internal sealed class WindowsCertificateStoreSigningOptionsValidator : ZeeKayDaOptionsValidator<WindowsCertificateStoreSigningOptions>
{
    /// <inheritdoc/>
    protected override void Validate(
        string? name,
        WindowsCertificateStoreSigningOptions options,
        ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (options.Current is null)
        {
            failures.Add(new(
                "configuration.windows_certificate_store_signing.current.missing",
                $"{nameof(WindowsCertificateStoreSigningOptions)}.{nameof(WindowsCertificateStoreSigningOptions.Current)} " +
                "must be set to the certificate that signs. Previous and Next are optional; Current is not."));
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            failures.Add(new(
                "configuration.windows_certificate_store_signing.algorithm.undefined_value",
                $"{nameof(WindowsCertificateStoreSigningOptions)}.{nameof(WindowsCertificateStoreSigningOptions.Algorithm)} " +
                $"value '{options.Algorithm}' is not a defined {nameof(SigningAlgorithm)} member."));
        }

        foreach (var failure in FindDuplicateSlots(options))
            failures.Add(failure);
    }

    /// <summary>
    /// Reports every pair of slots configured with the same certificate. Two slots naming one
    /// certificate is always a configuration mistake: it publishes the same key twice and, when
    /// <c>Current</c> is one of them, means a rotation that has not actually moved anything.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> FindDuplicateSlots(WindowsCertificateStoreSigningOptions options)
    {
        var slots = new (string Name, CertificateLookup? Lookup)[]
        {
            (nameof(WindowsCertificateStoreSigningOptions.Previous), options.Previous),
            (nameof(WindowsCertificateStoreSigningOptions.Current), options.Current),
            (nameof(WindowsCertificateStoreSigningOptions.Next), options.Next),
        };

        var configured = slots.Where(slot => slot.Lookup is not null).ToArray();

        // Compared as lookups, not as thumbprint strings: lookup equality covers the mode as well as
        // what it names, so a future mode is handled without revisiting this method.
        return from index in Enumerable.Range(0, configured.Length)
               from other in configured.Skip(index + 1)
               where configured[index].Lookup == other.Lookup
               select new ZeeKayDaConfigurationFailure(
                   "configuration.windows_certificate_store_signing.slots.duplicate_certificate",
                   $"{configured[index].Name} and {other.Name} are both configured with certificate " +
                   $"'{other.Lookup!.NormalizedThumbprint}'. Each slot must name a different certificate.");
    }
}
