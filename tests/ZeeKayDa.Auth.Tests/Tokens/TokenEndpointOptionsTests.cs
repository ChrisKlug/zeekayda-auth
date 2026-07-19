using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Tests for <see cref="TokenEndpointOptions.ComputeFamilyAbsoluteExpiry"/> — the sentinel-safe
/// birth-time conversion from <see cref="TokenEndpointOptions.AbsoluteFamilyLifetime"/> to a
/// concrete <c>FamilyAbsoluteExpiry</c> wall-clock (ADR 0014 §5).
/// </summary>
public sealed class TokenEndpointOptionsTests
{
    [Fact]
    public void ComputeFamilyAbsoluteExpiry_adds_AbsoluteFamilyLifetime_to_now()
    {
        var options = new TokenEndpointOptions { AbsoluteFamilyLifetime = TimeSpan.FromDays(90) };
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var result = options.ComputeFamilyAbsoluteExpiry(now);

        result.Should().Be(now + TimeSpan.FromDays(90));
    }

    [Fact]
    public void ComputeFamilyAbsoluteExpiry_returns_DateTimeOffsetMaxValue_for_the_TimeSpanMaxValue_sentinel()
    {
        var options = new TokenEndpointOptions { AbsoluteFamilyLifetime = TimeSpan.MaxValue };
        var now = DateTimeOffset.UtcNow;

        var result = options.ComputeFamilyAbsoluteExpiry(now);

        result.Should().Be(DateTimeOffset.MaxValue,
            because: "a naive now + TimeSpan.MaxValue overflows; the sentinel must map directly to DateTimeOffset.MaxValue");
    }

    [Fact]
    public void ComputeFamilyAbsoluteExpiry_does_not_throw_when_now_is_close_to_DateTimeOffsetMaxValue()
    {
        var options = new TokenEndpointOptions { AbsoluteFamilyLifetime = TimeSpan.FromDays(90) };
        var now = DateTimeOffset.MaxValue - TimeSpan.FromDays(1);

        var act = () => options.ComputeFamilyAbsoluteExpiry(now);

        act.Should().NotThrow();
    }

    [Fact]
    public void ComputeFamilyAbsoluteExpiry_falls_back_to_DateTimeOffsetMaxValue_when_the_addition_would_overflow()
    {
        var options = new TokenEndpointOptions { AbsoluteFamilyLifetime = TimeSpan.FromDays(90) };
        var now = DateTimeOffset.MaxValue - TimeSpan.FromDays(1);

        var result = options.ComputeFamilyAbsoluteExpiry(now);

        result.Should().Be(DateTimeOffset.MaxValue,
            because: "an overflowing non-sentinel addition degrades to the same unbounded ceiling rather than throwing");
    }
}
