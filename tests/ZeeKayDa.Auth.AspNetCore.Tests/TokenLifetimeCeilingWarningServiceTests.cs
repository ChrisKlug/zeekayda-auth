using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The startup warning for a server-wide token lifetime past the refresh-token family ceiling:
/// a token would then outlive the family that produced it.
/// </summary>
public sealed class TokenLifetimeCeilingWarningServiceTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private static TokenLifetimeCeilingWarningService BuildSut(
        TimeSpan? accessTokenLifetime = null,
        TimeSpan? idTokenLifetime = null,
        TimeSpan? absoluteFamilyLifetime = null)
    {
        var options = new AuthorizationServerOptions();
        options.TokenEndpoint.AbsoluteFamilyLifetime = absoluteFamilyLifetime ?? TimeSpan.FromDays(90);
        if (accessTokenLifetime is { } access)
            options.TokenEndpoint.AccessTokenLifetime = access;
        if (idTokenLifetime is { } id)
            options.TokenEndpoint.IdTokenLifetime = id;

        return new TokenLifetimeCeilingWarningService(new OptionsWrapper<AuthorizationServerOptions>(options));
    }

    [Fact]
    public async Task The_defaults_produce_no_warning()
    {
        var context = new StartupVerificationContext();

        await BuildSut().VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task An_access_token_lifetime_past_the_family_ceiling_warns()
    {
        var context = new StartupVerificationContext();

        await BuildSut(accessTokenLifetime: TimeSpan.FromDays(91))
            .VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("tokens.access_token_lifetime_exceeds_family_ceiling");
    }

    [Fact]
    public async Task An_ID_token_lifetime_past_the_family_ceiling_warns()
    {
        var context = new StartupVerificationContext();

        await BuildSut(idTokenLifetime: TimeSpan.FromDays(91))
            .VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("tokens.id_token_lifetime_exceeds_family_ceiling");
    }

    [Fact]
    public async Task A_lifetime_equal_to_the_ceiling_does_not_warn()
    {
        var context = new StartupVerificationContext();

        await BuildSut(accessTokenLifetime: TimeSpan.FromDays(90), idTokenLifetime: TimeSpan.FromDays(90))
            .VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty("the token expires with the family, not after it");
    }

    [Fact]
    public async Task No_finite_lifetime_exceeds_the_unbounded_ceiling()
    {
        var context = new StartupVerificationContext();

        await BuildSut(accessTokenLifetime: TimeSpan.FromDays(3650), absoluteFamilyLifetime: TimeSpan.MaxValue)
            .VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
    }
}
