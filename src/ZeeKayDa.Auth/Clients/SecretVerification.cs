namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The outcome of <see cref="ClientSecrets.Verify"/>: whether the presented secret matched, and
/// proof that a failure already spent its timing padding.
/// </summary>
/// <remarks>
/// Each failure vouches for its padding once, so one kept from an earlier request cannot excuse a later
/// refusal; a class, since a <c>default</c> struct would forge a padded failure.
/// </remarks>
public sealed class SecretVerification
{
    internal static readonly SecretVerification Match = new(matched: true);

    private int _paddingClaimed;

    private SecretVerification(bool matched) => Matched = matched;

    /// <summary>Whether the presented secret matched one of the stored secrets.</summary>
    public bool Matched { get; }

    internal static SecretVerification Mismatch() => new(matched: false);

    /// <summary>
    /// Whether this is a failure whose padding has not yet excused a refusal; true at most once.
    /// </summary>
    internal bool TryClaimPadding() => !Matched && Interlocked.Exchange(ref _paddingClaimed, 1) == 0;
}
