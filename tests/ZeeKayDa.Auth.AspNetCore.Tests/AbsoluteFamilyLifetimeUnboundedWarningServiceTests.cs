using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Tests for <see cref="AbsoluteFamilyLifetimeUnboundedWarningService"/> (ADR 0014 §5): the
/// startup-time warning emitted when <c>TokenEndpoint.AbsoluteFamilyLifetime</c> is left at the
/// <see cref="TimeSpan.MaxValue"/> unbounded escape-hatch sentinel.
/// </summary>
public sealed class AbsoluteFamilyLifetimeUnboundedWarningServiceTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private static AbsoluteFamilyLifetimeUnboundedWarningService BuildSut(TimeSpan absoluteFamilyLifetime)
    {
        var options = new AuthorizationServerOptions
        {
            TokenEndpoint = { AbsoluteFamilyLifetime = absoluteFamilyLifetime },
        };

        return new AbsoluteFamilyLifetimeUnboundedWarningService(
            new OptionsWrapper<AuthorizationServerOptions>(options));
    }

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new AbsoluteFamilyLifetimeUnboundedWarningService(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    // ── VerifyAsync: unbounded sentinel — warns ───────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_adds_a_warning_when_AbsoluteFamilyLifetime_is_TimeSpanMaxValue()
    {
        var sut = BuildSut(TimeSpan.MaxValue);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAsync_warning_code_is_tokens_absolute_family_lifetime_unbounded()
    {
        var sut = BuildSut(TimeSpan.MaxValue);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("tokens.absolute_family_lifetime_unbounded");
    }

    [Fact]
    public async Task VerifyAsync_warning_message_mentions_AbsoluteFamilyLifetime_when_unbounded()
    {
        var sut = BuildSut(TimeSpan.MaxValue);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

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

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_AbsoluteFamilyLifetimeUnbounded()
    {
        var sut = BuildSut(TimeSpan.FromDays(90));

        sut.Name.Should().Be("AbsoluteFamilyLifetimeUnbounded");
    }
}
