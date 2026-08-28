using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

public class ErrorInteractionTests
{
    [Fact]
    public async Task Returns_the_transported_error_for_the_current_request()
    {
        var transport = Transport();
        var write = new DefaultHttpContext();
        var id = transport.CreateAndAttach(write, "invalid_request", "The request is invalid.");

        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = write.Response.Headers.SetCookie.ToString().Split(';')[0];
        read.Request.QueryString = new QueryString(
            $"?{AuthorizeErrorTransport.QueryParameterName}={Uri.EscapeDataString(id)}");

        var interaction = new ErrorInteraction(new StaticAccessor(read), transport);
        var details = await interaction.GetErrorAsync(TestContext.Current.CancellationToken);

        details.Should().NotBeNull();
        details!.Error.Should().Be("invalid_request");
    }

    [Fact]
    public async Task Returns_null_when_the_request_carries_no_error()
    {
        var interaction = new ErrorInteraction(new StaticAccessor(new DefaultHttpContext()), Transport());

        var details = await interaction.GetErrorAsync(TestContext.Current.CancellationToken);

        details.Should().BeNull("the page should render a generic message, not fail");
    }

    [Fact]
    public async Task Throws_outside_an_active_request()
    {
        var interaction = new ErrorInteraction(new StaticAccessor(null), Transport());

        var act = () => interaction.GetErrorAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    private static AuthorizeErrorTransport Transport()
    {
        var options = new AuthorizationServerOptions();
        options.AuthorizationEndpoint.Interaction.ErrorPath = "/auth-error";
        return new AuthorizeErrorTransport(
            new EphemeralDataProtectionProvider(),
            Options.Create(options),
            new FakeTimeProvider(new DateTimeOffset(2026, 8, 28, 12, 0, 0, TimeSpan.Zero)));
    }

    private sealed class StaticAccessor(HttpContext? context) : IHttpContextAccessor
    {
        public HttpContext? HttpContext { get => context; set { } }
    }
}
