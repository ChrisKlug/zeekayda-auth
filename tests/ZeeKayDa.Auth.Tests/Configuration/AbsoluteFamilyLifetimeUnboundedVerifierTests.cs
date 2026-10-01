using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Configuration;

/// <summary>
/// Tests for <see cref="AbsoluteFamilyLifetimeUnboundedVerifier"/>: the
/// startup-time warning emitted when <c>TokenEndpoint.AbsoluteFamilyLifetime</c> is left at the
/// <see cref="TimeSpan.MaxValue"/> unbounded escape-hatch sentinel.
/// </summary>
public sealed class AbsoluteFamilyLifetimeUnboundedVerifierTests
{
    private static AbsoluteFamilyLifetimeUnboundedVerifier BuildSut(TimeSpan absoluteFamilyLifetime)
    {
        var options = new AuthorizationServerOptions
        {
            TokenEndpoint = { AbsoluteFamilyLifetime = absoluteFamilyLifetime },
        };

        return new AbsoluteFamilyLifetimeUnboundedVerifier(
            new OptionsWrapper<AuthorizationServerOptions>(options));
    }

    // ── VerifyAsync: unbounded sentinel — warns ───────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_adds_a_warning_when_AbsoluteFamilyLifetime_is_TimeSpanMaxValue()
    {
        var sut = BuildSut(TimeSpan.MaxValue);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAsync_warning_code_is_tokens_absolute_family_lifetime_unbounded()
    {
        var sut = BuildSut(TimeSpan.MaxValue);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("tokens.absolute_family_lifetime_unbounded");
    }

    [Fact]
    public async Task VerifyAsync_warning_message_mentions_AbsoluteFamilyLifetime_when_unbounded()
    {
        var sut = BuildSut(TimeSpan.MaxValue);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.MessageTemplate.Should().Contain("AbsoluteFamilyLifetime");
    }

    // ── VerifyAsync: finite lifetime — no-op ──────────────────────────────────────────────────────

    [Theory]
    [InlineData(90)]
    [InlineData(1)]
    [InlineData(3650)]
    public async Task VerifyAsync_does_not_add_a_warning_when_AbsoluteFamilyLifetime_is_finite(int days)
    {
        var sut = BuildSut(TimeSpan.FromDays(days));
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
    }
}
