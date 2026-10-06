namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The arithmetic every token lifetime shares: a client override that inherits the server value
/// when <see langword="null"/>, and expiries and sums that saturate instead of throwing.
/// </summary>
internal static class TokenLifetimes
{
    /// <summary>The lifetime in force for one client: its own override, or the server's value.</summary>
    public static TimeSpan Effective(TimeSpan? clientOverride, TimeSpan serverDefault) =>
        clientOverride ?? serverDefault;

    /// <summary>
    /// <paramref name="now"/> plus <paramref name="lifetime"/>, saturating at
    /// <see cref="DateTimeOffset.MaxValue"/>. Every lifetime that reaches here passed startup
    /// validation, so no configured value may fail at issuance — including the
    /// <see cref="TimeSpan.MaxValue"/> sentinel, whose naive addition overflows.
    /// </summary>
    public static DateTimeOffset ExpiresAt(DateTimeOffset now, TimeSpan lifetime)
    {
        if (lifetime == TimeSpan.MaxValue)
            return DateTimeOffset.MaxValue;

        try
        {
            return now + lifetime;
        }
        catch (ArgumentOutOfRangeException)
        {
            return DateTimeOffset.MaxValue;
        }
    }

    /// <summary>
    /// Two durations added together, saturating at <see cref="TimeSpan.MaxValue"/> and
    /// <see cref="TimeSpan.MinValue"/> rather than throwing, so even an invalid negative setting
    /// reaches its own validation rule.
    /// </summary>
    public static TimeSpan Sum(TimeSpan first, TimeSpan second)
    {
        if (second > TimeSpan.Zero && first > TimeSpan.MaxValue - second)
            return TimeSpan.MaxValue;

        if (second < TimeSpan.Zero && first < TimeSpan.MinValue - second)
            return TimeSpan.MinValue;

        return first + second;
    }
}
