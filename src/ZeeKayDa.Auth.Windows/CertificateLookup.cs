namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// How to find one certificate in the configured Windows Certificate Store — the value configured
/// into each of <see cref="WindowsCertificateStoreSigningOptions"/>'s three signing key slots.
/// </summary>
/// <remarks>
/// <para>
/// A lookup names a certificate; it is not the certificate itself, and it carries no key material.
/// The store to search is not part of it: <see cref="WindowsCertificateStoreSigningOptions.StoreLocation"/>
/// and <see cref="WindowsCertificateStoreSigningOptions.StoreName"/> apply to every slot alike.
/// </para>
/// <para>
/// <see cref="ByThumbprint"/> is the only way to construct one today. Lookup by subject name is
/// deliberately absent: a subject name can match several certificates, so deciding which of them
/// signs is a security question in its own right rather than a detail of this type.
/// </para>
/// </remarks>
public sealed record CertificateLookup
{
    private CertificateLookup(string thumbprint) => Thumbprint = thumbprint;

    /// <summary>
    /// Gets the normalized, uppercase-hex thumbprint of the certificate this lookup finds. Never
    /// empty.
    /// </summary>
    public string Thumbprint { get; }

    /// <summary>
    /// Creates a lookup that finds a certificate by thumbprint.
    /// </summary>
    /// <param name="thumbprint">
    /// The certificate's thumbprint. Copy-paste artifacts are tolerated: every character that is
    /// not a hex digit is stripped and the remainder uppercased, so the embedded spaces and the
    /// invisible leading U+200E LEFT-TO-RIGHT MARK that <c>certmgr</c> and the Certificates MMC
    /// snap-in add when a thumbprint is copied from their UI do not have to be cleaned up by hand.
    /// </param>
    /// <returns>A lookup for the normalized thumbprint.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="thumbprint"/> is null, empty, whitespace, or contains no hex
    /// digits at all — none of which can name a certificate. Rejecting them here, rather than at
    /// startup validation, means the exception names the offending call rather than the options
    /// object it ended up on, and makes a non-empty <see cref="Thumbprint"/> true by construction.
    /// </exception>
    public static CertificateLookup ByThumbprint(string thumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);

        var normalized = ThumbprintFormat.Normalize(thumbprint);
        if (normalized.Length == 0)
        {
            throw new ArgumentException(
                $"'{thumbprint}' contains no hex digits, so it cannot be a certificate thumbprint. " +
                "Verify the thumbprint was copied correctly.",
                nameof(thumbprint));
        }

        return new CertificateLookup(normalized);
    }
}
