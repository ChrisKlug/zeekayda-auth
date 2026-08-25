using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Validates <see cref="WindowsCertificateStoreSigningOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddWindowsCertificateStoreSigning()</c> and activated by <c>ValidateOnStart()</c>.
/// There is no empty-thumbprint check here: <see cref="CertificateLookup.ByThumbprint"/> rejects a
/// thumbprint with no hex digits at construction, so a configured slot always holds a usable one.
/// </remarks>
internal sealed class WindowsCertificateStoreSigningOptionsValidator : IValidateOptions<WindowsCertificateStoreSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, WindowsCertificateStoreSigningOptions options)
    {
        var errors = new List<string>();

        if (options.Current is null)
        {
            errors.Add(
                $"{nameof(WindowsCertificateStoreSigningOptions)}.{nameof(WindowsCertificateStoreSigningOptions.Current)} " +
                "must be set to the certificate that signs. Previous and Next are optional; Current is not.");
        }

        if (!Enum.IsDefined(options.Algorithm))
        {
            errors.Add(
                $"{nameof(WindowsCertificateStoreSigningOptions)}.{nameof(WindowsCertificateStoreSigningOptions.Algorithm)} " +
                $"value '{options.Algorithm}' is not a defined {nameof(SigningAlgorithm)} member.");
        }

        errors.AddRange(FindDuplicateSlotErrors(options));

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    /// <summary>
    /// Reports every pair of slots configured with the same certificate. Two slots naming one
    /// certificate is always a configuration mistake: it publishes the same key twice and, when
    /// <c>Current</c> is one of them, means a rotation that has not actually moved anything.
    /// </summary>
    private static IEnumerable<string> FindDuplicateSlotErrors(WindowsCertificateStoreSigningOptions options)
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
               select $"{configured[index].Name} and {other.Name} are both configured with certificate " +
                      $"'{other.Lookup!.NormalizedThumbprint}'. Each slot must name a different certificate.";
    }
}
