namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The arithmetic every token lifetime shares: a client override that inherits the server value
/// when <see langword="null"/>, and an expiry that saturates instead of throwing.
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
}
