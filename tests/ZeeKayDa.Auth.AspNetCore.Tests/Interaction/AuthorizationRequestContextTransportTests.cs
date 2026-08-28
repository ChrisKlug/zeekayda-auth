using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The interaction cookie (#84): the encrypted, chunked transport that carries the authorization
/// request context across the redirects of the authorize flow. There is no store behind it.
/// </summary>
public class AuthorizationRequestContextTransportTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 28, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Written_context_round_trips_through_the_cookie()
    {
        var transport = Transport(out _);
        var write = new DefaultHttpContext();
        var context = ContextAt(Now);

        transport.TryWrite(write, context).Should().BeTrue();

        transport.TryRead(ReadContextFrom(write)).Should().BeEquivalentTo(context);
    }

    [Fact]
    public void Largest_writable_context_still_round_trips()
    {
        // Chunking is ChunkingCookieManager's job, not ours; at the guard the payload sits close
        // to one cookie's capacity, so this proves we delegate rather than silently writing an
        // over-long cookie the browser would drop.
        var transport = Transport(out _);
        var (write, context) = WriteLargestAcceptedContext(transport);

        transport.TryRead(ReadContextFrom(write)).Should().BeEquivalentTo(context);
    }

    [Fact]
    public void Largest_writable_context_stays_within_the_request_header_budget()
    {
        // The guard exists to bound the *request* header, not to fill a cookie. Everything written
        // here is re-sent on every request to Path=/ beside the session, pending and host cookies,
        // so an over-generous ceiling lets a hostile authorize request wedge the victim's browser
        // against the issuer host for the interaction's full lifetime.
        var transport = Transport(out _);
        var (write, _) = WriteLargestAcceptedContext(transport);

        var cookieHeaderBytes = write.Response.Headers.SetCookie
            .Sum(header => header!.Split(';')[0].Length);

        cookieHeaderBytes.Should().BeLessThan(4_608,
            "the interaction cookie alone must fit inside the tightest common proxy header " +
            "buffer with room left for the session, pending and host cookies");
    }

    [Fact]
    public void Context_over_the_size_guard_is_refused_and_nothing_is_written()
    {
        // No inbound parameter is length-capped, so the guard is here — and it must fail before
        // minting a cookie a proxy would reject on the next hop.
        var transport = Transport(out _);
        var write = new DefaultHttpContext();
        var context = ContextAt(Now) with { State = new string('s', 20_000) };

        transport.TryWrite(write, context).Should().BeFalse();

        write.Response.Headers.SetCookie.Should().BeEmpty();
    }

    [Fact]
    public void Expired_context_reads_nothing()
    {
        var transport = Transport(out var time);
        var write = new DefaultHttpContext();
        transport.TryWrite(write, ContextAt(Now)).Should().BeTrue();

        time.Advance(AuthorizationRequestContextTransport.Lifetime + TimeSpan.FromSeconds(1));

        transport.TryRead(ReadContextFrom(write)).Should().BeNull();
    }

    [Fact]
    public void Expiry_is_read_from_the_payload_not_the_cookie()
    {
        // A client controls when it stops sending a cookie. The copy inside the encrypted payload
        // is the one it cannot edit, so that is the one enforced.
        var transport = Transport(out var time);
        var write = new DefaultHttpContext();
        transport.TryWrite(write, ContextAt(Now) with { ExpiresAt = Now.AddMinutes(1) }).Should().BeTrue();

        time.Advance(TimeSpan.FromMinutes(2));

        transport.TryRead(ReadContextFrom(write)).Should().BeNull(
            "the payload expired even though the cookie's own MaxAge had not");
    }

    [Fact]
    public void Tampered_cookie_reads_nothing_and_does_not_throw()
    {
        var transport = Transport(out _);
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{AuthorizationRequestContextTransport.CookieName}=dGFtcGVyZWQ=";

        transport.TryRead(read).Should().BeNull();
    }

    [Fact]
    public void Cookie_protected_under_another_key_reads_nothing()
    {
        var write = new DefaultHttpContext();
        Transport(out _).TryWrite(write, ContextAt(Now)).Should().BeTrue();

        // A second application, or the same one after a key-ring loss.
        Transport(out _).TryRead(ReadContextFrom(write)).Should().BeNull();
    }

    [Fact]
    public void Absent_cookie_reads_nothing()
    {
        Transport(out _).TryRead(new DefaultHttpContext()).Should().BeNull();
    }

    [Fact]
    public void Deleting_clears_the_cookie()
    {
        var transport = Transport(out _);
        var delete = new DefaultHttpContext();

        transport.Delete(delete);

        var setCookie = delete.Response.Headers.SetCookie.ToString();
        setCookie.Should().Contain(AuthorizationRequestContextTransport.CookieName)
            .And.Contain("expires=Thu, 01 Jan 1970");
    }

    [Fact]
    public void Cookie_is_HttpOnly_Secure_Lax_and_rooted()
    {
        var transport = Transport(out _);
        var write = new DefaultHttpContext();

        transport.TryWrite(write, ContextAt(Now)).Should().BeTrue();

        var setCookie = write.Response.Headers.SetCookie.ToString();
        setCookie.Should().Contain("httponly")
            .And.Contain("secure")
            .And.Contain("samesite=lax")
            .And.Contain("path=/");
    }

    [Fact]
    public void Cookie_value_is_opaque()
    {
        // Nothing in the context may be readable from the wire — the redirect URI, scopes and
        // nonce are all in there.
        var transport = Transport(out _);
        var write = new DefaultHttpContext();

        transport.TryWrite(write, ContextAt(Now)).Should().BeTrue();

        var setCookie = write.Response.Headers.SetCookie.ToString();
        setCookie.Should().NotContain("client.example.com").And.NotContain("n-0S6_WzA2Mj");
    }

    [Fact]
    public void Context_is_not_readable_at_the_expiry_instant()
    {
        var transport = Transport(out var time);
        var write = new DefaultHttpContext();
        transport.TryWrite(write, ContextAt(Now)).Should().BeTrue();

        time.Advance(AuthorizationRequestContextTransport.Lifetime);

        transport.TryRead(ReadContextFrom(write)).Should().BeNull(
            "expiry is exclusive — the instant the window closes is outside it");
    }

    [Fact]
    public void Error_transport_cookie_cannot_be_read_as_an_interaction_context()
    {
        // Both cookies are protected on the same key ring. Only the Data Protection purpose keeps
        // one from being accepted as the other, so it is worth an assertion rather than trust.
        var time = new FakeTimeProvider(Now);
        var keyRing = new EphemeralDataProtectionProvider();

        var options = new AuthorizationServerOptions();
        options.AuthorizationEndpoint.Interaction.ErrorPath = "/auth-error";
        var errorTransport = new AuthorizeErrorTransport(keyRing, Options.Create(options), time);

        var write = new DefaultHttpContext();
        errorTransport.CreateAndAttach(write, "invalid_request", "The request is invalid.");

        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie =
            $"{AuthorizationRequestContextTransport.CookieName}=" +
            write.Response.Headers.SetCookie.ToString().Split('=')[1].Split(';')[0];

        new AuthorizationRequestContextTransport(keyRing, time).TryRead(read).Should().BeNull();
    }

    [Fact]
    public void Interaction_cookie_cannot_be_read_as_an_error_transport_cookie()
    {
        var time = new FakeTimeProvider(Now);
        var keyRing = new EphemeralDataProtectionProvider();

        var write = new DefaultHttpContext();
        new AuthorizationRequestContextTransport(keyRing, time).TryWrite(write, ContextAt(Now))
            .Should().BeTrue();

        var options = new AuthorizationServerOptions();
        options.AuthorizationEndpoint.Interaction.ErrorPath = "/auth-error";

        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie =
            $"{AuthorizeErrorTransport.CookieName}=" +
            write.Response.Headers.SetCookie.ToString().Split('=')[1].Split(';')[0];
        read.Request.QueryString = new QueryString($"?{AuthorizeErrorTransport.QueryParameterName}=any");

        new AuthorizeErrorTransport(keyRing, Options.Create(options), time).TryRead(read)
            .Should().BeNull();
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static AuthorizationRequestContextTransport Transport(out FakeTimeProvider time)
    {
        time = new FakeTimeProvider(Now);
        return new AuthorizationRequestContextTransport(new EphemeralDataProtectionProvider(), time);
    }

    /// <summary>
    /// Writes the largest context the size guard accepts, found by growing <c>state</c> until it
    /// is refused. Derived rather than hard-coded: the encrypted payload's exact size depends on
    /// the Data Protection version, and a constant here would silently stop testing the boundary.
    /// </summary>
    private static (DefaultHttpContext Written, AuthorizationRequestContext Context)
        WriteLargestAcceptedContext(AuthorizationRequestContextTransport transport)
    {
        DefaultHttpContext? accepted = null;
        AuthorizationRequestContext? acceptedContext = null;
        var reachedTheGuard = false;

        for (var length = 0; length <= 8_000; length += 50)
        {
            var candidate = new DefaultHttpContext();
            var context = ContextAt(Now) with { State = new string('s', length) };

            if (!transport.TryWrite(candidate, context))
            {
                reachedTheGuard = true;
                break;
            }

            accepted = candidate;
            acceptedContext = context;
        }

        accepted.Should().NotBeNull("the guard must accept a context of some size");
        // Without this the search fails open: raise MaxProtectedPayloadBytes past what the loop's
        // ceiling produces and every caller would quietly assert on a non-boundary case.
        reachedTheGuard.Should().BeTrue(
            "the search must actually reach the guard, not run out of candidates below it");

        return (accepted!, acceptedContext!);
    }

    private static DefaultHttpContext ReadContextFrom(HttpContext written)
    {
        // Re-present every Set-Cookie value as a request Cookie header, the way a browser would —
        // chunked payloads span several of them.
        var pairs = written.Response.Headers.SetCookie
            .Select(header => header!.Split(';')[0]);

        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = string.Join("; ", pairs);
        return read;
    }

    private static AuthorizationRequestContext ContextAt(DateTimeOffset now) => new()
    {
        Id = "interaction-id",
        ClientId = "test-client",
        RedirectUri = "https://client.example.com/callback",
        Scopes = ["openid"],
        State = null,
        Nonce = "n-0S6_WzA2Mj",
        CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        CodeChallengeMethod = CodeChallengeMethod.S256,
        Prompts = new HashSet<PromptValue>(),
        MaxAge = null,
        IssuedAt = now,
        ExpiresAt = now + AuthorizationRequestContextTransport.Lifetime,
    };
}
