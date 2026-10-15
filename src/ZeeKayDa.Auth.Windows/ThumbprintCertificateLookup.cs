namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// A <see cref="CertificateLookup"/> that finds its certificate by thumbprint. Created by
/// <see cref="CertificateLookup.ByThumbprint"/>.
/// </summary>
/// <remarks>
/// Two lookups are equal when they name the same certificate, however each thumbprint was written.
/// </remarks>
public sealed class ThumbprintCertificateLookup : CertificateLookup
{
    // Internal, so ByThumbprint's normalization and validation cannot be bypassed.
    internal ThumbprintCertificateLookup(string thumbprint) => Thumbprint = thumbprint;

    /// <summary>The normalized, uppercase-hex thumbprint this lookup finds; never empty.</summary>
    public string Thumbprint { get; }

    /// <inheritdoc/>
    internal override string NormalizedThumbprint => Thumbprint;

    /// <inheritdoc/>
    private protected override bool EqualsCore(CertificateLookup other) =>
        string.Equals(Thumbprint, ((ThumbprintCertificateLookup)other).Thumbprint, StringComparison.Ordinal);

    /// <inheritdoc/>
    private protected override int GetHashCodeCore() => StringComparer.Ordinal.GetHashCode(Thumbprint);

    /// <summary>Returns a description naming the thumbprint, which is public information.</summary>
    public override string ToString() => $"thumbprint {Thumbprint}";
}
