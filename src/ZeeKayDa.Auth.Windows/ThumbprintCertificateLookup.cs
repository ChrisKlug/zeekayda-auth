namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// A <see cref="CertificateLookup"/> that finds its certificate by thumbprint. Created by
/// <see cref="CertificateLookup.ByThumbprint"/>.
/// </summary>
/// <remarks>
/// Two lookups are equal when they are the same mode and name the same certificate, which is how
/// <see cref="WindowsCertificateStoreSigningOptionsValidator"/> detects two slots configured with
/// one certificate however each thumbprint happened to be written.
/// </remarks>
public sealed class ThumbprintCertificateLookup : CertificateLookup
{
    // Internal: the only way to obtain one is CertificateLookup.ByThumbprint, so the normalization
    // and validation it performs cannot be bypassed.
    internal ThumbprintCertificateLookup(string thumbprint) => Thumbprint = thumbprint;

    /// <summary>
    /// Gets the normalized, uppercase-hex thumbprint of the certificate this lookup finds. Never
    /// empty.
    /// </summary>
    public string Thumbprint { get; }

    /// <inheritdoc/>
    internal override string NormalizedThumbprint => Thumbprint;

    /// <inheritdoc/>
    /// <remarks>
    /// The cast is safe: <see cref="CertificateLookup.Equals(CertificateLookup)"/> has already
    /// established that <paramref name="other"/> is non-null and of exactly this type.
    /// </remarks>
    private protected override bool EqualsCore(CertificateLookup other) =>
        string.Equals(Thumbprint, ((ThumbprintCertificateLookup)other).Thumbprint, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Thumbprint);

    /// <summary>
    /// Returns a diagnostic description naming the thumbprint. A thumbprint is public information —
    /// it is derived from the certificate's public encoding — so this carries nothing sensitive.
    /// </summary>
    public override string ToString() => $"thumbprint {Thumbprint}";
}
