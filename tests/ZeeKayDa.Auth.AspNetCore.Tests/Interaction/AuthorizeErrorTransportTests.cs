using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

public class AuthorizeErrorTransportTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 28, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Attached_error_round_trips_through_cookie_and_id()
    {
        var transport = Transport(out var time);
        var write = new DefaultHttpContext();

        var id = transport.CreateAndAttach(write, "invalid_request", "The request is invalid.");
        var read = ContextWithCookieFrom(write, id);

        var details = transport.TryRead(read);
        details.Should().NotBeNull();
        details!.Error.Should().Be("invalid_request");
        details.Description.Should().Be("The request is invalid.");
    }

    [Fact]
    public void Mismatched_error_id_reads_nothing()
    {
        var transport = Transport(out _);
        var write = new DefaultHttpContext();

        transport.CreateAndAttach(write, "invalid_request", "The request is invalid.");
        var read = ContextWithCookieFrom(write, "a-different-id");

        transport.TryRead(read).Should().BeNull(
            "the cookie must be bound to the id issued with it — a stale cookie from another " +
            "error must not answer for this one");
    }

    [Fact]
    public void Expired_transport_reads_nothing()
    {
        var transport = Transport(out var time);
        var write = new DefaultHttpContext();

        var id = transport.CreateAndAttach(write, "invalid_request", "The request is invalid.");
        time.Advance(TimeSpan.FromMinutes(3));

        transport.TryRead(ContextWithCookieFrom(write, id)).Should().BeNull();
    }

    [Fact]
    public void Tampered_cookie_reads_nothing_and_does_not_throw()
    {
        var transport = Transport(out _);
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{AuthorizeErrorTransport.CookieName}=dGFtcGVyZWQ=";
        read.Request.QueryString = new QueryString($"?{AuthorizeErrorTransport.QueryParameterName}=any");

        transport.TryRead(read).Should().BeNull();
    }

    [Fact]
    public void Cookie_is_HttpOnly_and_scoped_to_the_error_path()
    {
        var transport = Transport(out _);
        var write = new DefaultHttpContext();

        transport.CreateAndAttach(write, "invalid_request", "The request is invalid.");

        var setCookie = write.Response.Headers.SetCookie.ToString();
        setCookie.Should().Contain("httponly").And.Contain("path=/auth-error");
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static AuthorizeErrorTransport Transport(out FakeTimeProvider time)
    {
        time = new FakeTimeProvider(Now);
        var options = new AuthorizationServerOptions();
        options.AuthorizationEndpoint.Interaction.ErrorPath = "/auth-error";

        return new AuthorizeErrorTransport(
            new EphemeralDataProtectionProvider(), Options.Create(options), time);
    }

    private static DefaultHttpContext ContextWithCookieFrom(HttpContext written, string id)
    {
        // Re-present the Set-Cookie value as a request Cookie header, the way a browser would.
        var setCookie = written.Response.Headers.SetCookie.ToString();
        var cookiePair = setCookie.Split(';')[0];

        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = cookiePair;
        read.Request.QueryString = new QueryString(
            $"?{AuthorizeErrorTransport.QueryParameterName}={Uri.EscapeDataString(id)}");
        return read;
    }
}
