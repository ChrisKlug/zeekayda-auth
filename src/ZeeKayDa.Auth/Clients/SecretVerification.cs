namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The outcome of <see cref="IClientSecrets.Verify"/>: whether the presented secret matched, and
/// proof that a failure already spent its timing padding.
/// </summary>
/// <remarks>
/// Only <see cref="IClientSecrets.Verify"/> creates one, so holding a failed verification means the
/// failure was padded. A class rather than a struct: <c>default</c> would forge an unpadded failure.
/// </remarks>
public sealed class SecretVerification
{
    internal static readonly SecretVerification Match = new(matched: true);
    internal static readonly SecretVerification Mismatch = new(matched: false);

    private SecretVerification(bool matched) => Matched = matched;

    /// <summary>Whether the presented secret matched one of the stored secrets.</summary>
    public bool Matched { get; }
}
