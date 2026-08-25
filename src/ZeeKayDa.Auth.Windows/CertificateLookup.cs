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
/// One lookup mode ships today, <see cref="ByThumbprint"/>, returning a
/// <see cref="ThumbprintCertificateLookup"/>. Each mode is its own derived type, and each factory
/// here is declared to return this base type, so adding a mode later adds a type and a factory
/// without changing the shape of anything already published. Lookup by subject name is deliberately
/// absent: a subject name can match several certificates, so deciding which of them signs is a
/// security question in its own right rather than a detail of this type.
/// </para>
/// <para>
/// The hierarchy is closed — the constructor is <see langword="private protected"/>, so only this
/// assembly can derive. Consumers construct lookups through the factories and never implement their
/// own.
/// </para>
/// <para>
/// A hand-written class rather than a <see langword="record"/>: a record hierarchy would publish a
/// synthesized <c>&lt;Clone&gt;$</c>, <c>PrintMembers</c> and <c>EqualityContract</c> on every type
/// here, and its <c>with</c> expression would become a way to build a lookup that never passed
/// through <see cref="ByThumbprint"/> the moment any derived type gained an <c>init</c> member.
/// Equality is the only synthesized member this type actually wants, so it is written out instead.
/// </para>
/// </remarks>
public abstract class CertificateLookup : IEquatable<CertificateLookup>
{
    private protected CertificateLookup()
    {
    }

    /// <summary>
    /// Gets the normalized, uppercase-hex thumbprint of the certificate this lookup finds. Never
    /// empty.
    /// </summary>
    /// <remarks>
    /// <see langword="internal"/> on purpose: <b>how</b> a lookup resolves to a store entry is not
    /// part of the public contract. Every mode that exists today resolves to a thumbprint without
    /// touching the store, but a future mode that has to query the store to resolve — subject name,
    /// say — cannot be expressed by a plain string property. Keeping this member internal means
    /// reshaping it then is not a breaking change.
    /// </remarks>
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
    /// digits at all — none of which can name a certificate. Rejecting them here, rather than at
    /// startup validation, means the exception names the offending call rather than the options
    /// object it ended up on, and makes a non-empty thumbprint true by construction.
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
    public abstract bool Equals(CertificateLookup? other);

    /// <inheritdoc/>
    public abstract override int GetHashCode();

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CertificateLookup);

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
