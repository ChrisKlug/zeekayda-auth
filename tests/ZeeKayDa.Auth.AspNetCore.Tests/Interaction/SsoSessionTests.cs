using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>The SSO session a promotion establishes.</summary>
public sealed class SsoSessionTests
{
    [Fact]
    public async Task PromoteAsync_establishes_the_session_for_the_subject()
    {
        using var host = new EndpointHost();
        await host.EnsureStartedAsync();
        await using var scope = host.Services.CreateAsyncScope();
        var context = host.Get("/sign-in").Build(scope.ServiceProvider);
        var state = await scope.ServiceProvider.GetRequiredService<SsoSession>().PromoteAsync(context, new SignIn(SessionSubject.From("user-1"), [], ProviderScheme: null, new AccountPlacement(LoginIdentifier: null, AddAccount: false), AuthenticatedAt: null), "client-1");

        state.Subject.Should().Be("user-1");
    }
}
