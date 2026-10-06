using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>Where the SSO session reads the subject of the principal it promotes.</summary>
public sealed class SsoSessionTests
{
    [Fact]
    public async Task PromoteAsync_reads_the_subject_from_sub_only()
    {
        // One subject source: a NameIdentifier is never taken as the session subject, however a
        // future caller builds its principal.
        using var host = new EndpointHost();
        await host.EnsureStartedAsync();
        await using var scope = host.Services.CreateAsyncScope();
        var context = host.Get("/sign-in").Build(scope.ServiceProvider);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "user-1")], "test"));

        var promote = () => scope.ServiceProvider.GetRequiredService<SsoSession>().PromoteAsync(context, principal, []);

        await promote.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task PromoteAsync_establishes_the_session_for_the_sub_claim()
    {
        using var host = new EndpointHost();
        await host.EnsureStartedAsync();
        await using var scope = host.Services.CreateAsyncScope();
        var context = host.Get("/sign-in").Build(scope.ServiceProvider);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test"));

        var state = await scope.ServiceProvider.GetRequiredService<SsoSession>().PromoteAsync(context, principal, []);

        state.Subject.Should().Be("user-1");
    }
}
