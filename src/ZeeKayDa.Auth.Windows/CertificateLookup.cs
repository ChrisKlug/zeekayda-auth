namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// How to find one certificate in the configured Windows Certificate Store — one entry of
/// <see cref="WindowsCertificateStoreSigningOptions.Certificates"/>.
/// </summary>
/// <remarks>
/// <para>
/// A lookup names a certificate; it is not the certificate itself, and it carries no key material.
/// The store to search is not part of it: <see cref="WindowsCertificateStoreSigningOptions.StoreLocation"/>
/// and <see cref="WindowsCertificateStoreSigningOptions.StoreName"/> apply to every listed certificate alike.
/// </para>
/// <para>
/// Create one with a factory such as <see cref="ByThumbprint"/>; the hierarchy is closed to other
/// assemblies. There is no lookup by subject name, because a subject name can match several
/// certificates.
/// </para>
/// </remarks>
public abstract class CertificateLookup : IEquatable<CertificateLookup>
{
    private protected CertificateLookup()
    {
    }

    /// <summary>The normalized, uppercase-hex thumbprint this lookup finds; never empty.</summary>
    internal abstract string NormalizedThumbprint { get; }

    /// <summary>
    /// Creates a lookup that finds a certificate by thumbprint.
    /// </summary>
    /// <param name="thumbprint">
    /// The certificate's thumbprint. Copy-paste artifacts are tolerated: every character that is
    /// not a hex digit is stripped and the remainder uppercased, so the embedded spaces and the
    /// invisible leading U+200E LEFT-TO-RIGHT MARK that <c>certmgr</c> and the Certificates MMC
    /// snap-in add when a thumbprint is copied from their UI do not have to be cleaned up by hand.
    /// </param>
    /// <returns>A <see cref="ThumbprintCertificateLookup"/> for the normalized thumbprint.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="thumbprint"/> is null, empty, whitespace, or contains no hex
    /// digits at all — none of which can name a certificate.
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

        return new ThumbprintCertificateLookup(normalized);
    }

    /// <summary>
    /// Determines whether this lookup and <paramref name="other"/> are the same lookup mode naming
    /// the same certificate.
    /// </summary>
    /// <param name="other">The lookup to compare with.</param>
    /// <returns><see langword="true"/> when both name the same certificate the same way.</returns>
    public bool Equals(CertificateLookup? other) =>
        other is not null && other.GetType() == GetType() && EqualsCore(other);

    /// <summary>Compares with <paramref name="other"/>, already checked non-null and of exactly this type.</summary>
    private protected abstract bool EqualsCore(CertificateLookup other);

    /// <inheritdoc/>
    public sealed override int GetHashCode() => HashCode.Combine(GetType(), GetHashCodeCore());

    /// <summary>A hash code consistent with <see cref="EqualsCore"/>.</summary>
    private protected abstract int GetHashCodeCore();

    /// <inheritdoc/>
    public sealed override bool Equals(object? obj) =>
        obj is not null && obj.GetType() == GetType() && EqualsCore((CertificateLookup)obj);

    /// <summary>Determines whether two lookups name the same certificate the same way.</summary>
    /// <param name="left">The first lookup, or <see langword="null"/>.</param>
    /// <param name="right">The second lookup, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when both are <see langword="null"/> or both name the same
    /// certificate the same way.</returns>
    public static bool operator ==(CertificateLookup? left, CertificateLookup? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two lookups differ.</summary>
    /// <param name="left">The first lookup, or <see langword="null"/>.</param>
    /// <param name="right">The second lookup, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> and <paramref name="right"/> do
    /// not name the same certificate the same way.</returns>
    public static bool operator !=(CertificateLookup? left, CertificateLookup? right) => !(left == right);
}
