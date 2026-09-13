using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// The arithmetic every token lifetime shares: a null client override inherits, and no value
/// that passed startup validation can fail at issuance.
/// </summary>
public sealed class TokenLifetimesTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_client_override_wins_over_the_server_value()
    {
        TokenLifetimes.Effective(TimeSpan.FromMinutes(10), TimeSpan.FromHours(1))
            .Should().Be(TimeSpan.FromMinutes(10));
    }

    [Fact]
    public void A_null_override_inherits_the_server_value()
    {
        TokenLifetimes.Effective(null, TimeSpan.FromHours(1)).Should().Be(TimeSpan.FromHours(1));
    }

    [Fact]
    public void An_expiry_is_now_plus_the_lifetime()
    {
        TokenLifetimes.ExpiresAt(Now, TimeSpan.FromHours(1)).Should().Be(Now.AddHours(1));
    }

    [Fact]
    public void The_unbounded_sentinel_saturates_instead_of_overflowing()
    {
        TokenLifetimes.ExpiresAt(Now, TimeSpan.MaxValue).Should().Be(DateTimeOffset.MaxValue);
    }

    [Fact]
    public void A_lifetime_that_overflows_the_clock_saturates_instead_of_throwing()
    {
        // Not the sentinel, but still past what DateTimeOffset can hold from this instant.
        TokenLifetimes.ExpiresAt(Now, TimeSpan.FromDays(4_000_000)).Should().Be(DateTimeOffset.MaxValue);
    }
}
