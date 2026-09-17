using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The per-interaction binding cookie: the one thing that ties an interaction identifier, which
/// travels in URLs, to the browser that started the request.
/// </summary>
public sealed class InteractionBindingCookieTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ExpiresAt = Now.AddMinutes(30);

    [Fact]
    public void Issued_secret_reads_back_from_the_cookie_it_was_written_to()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        var secret = InteractionBindingCookie.NewSecret();
        binding.Issue(write, "interaction-a", ExpiresAt, secret, clientId: null);

        binding.Read(RequestCarrying(write), "interaction-a").Should().Be(secret);
    }

    [Fact]
    public void Secret_is_random_and_never_reused()
    {
        var first = InteractionBindingCookie.NewSecret();
        var second = InteractionBindingCookie.NewSecret();

        first.Should().NotBe(second);
        first.Should().HaveLength(43, "256 bits of CSPRNG output, Base64Url-encoded");
    }

    [Fact]
    public void Cookie_is_named_for_its_interaction()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), clientId: null);

        write.Response.Headers.SetCookie.ToString()
            .Should().StartWith(InteractionBindingCookie.NamePrefix + "interaction-a=");
    }

    [Fact]
    public void Two_interactions_hold_two_cookies_and_each_reads_its_own()
    {
        // Concurrent tabs share nothing: the second authorize request does not replace the first.
        var binding = Binding();
        var write = new DefaultHttpContext();

        var first = InteractionBindingCookie.NewSecret();
        var second = InteractionBindingCookie.NewSecret();
        binding.Issue(write, "interaction-a", ExpiresAt, first, clientId: null);
        binding.Issue(write, "interaction-b", ExpiresAt, second, clientId: null);

        var read = RequestCarrying(write);
        binding.Read(read, "interaction-a").Should().Be(first);
        binding.Read(read, "interaction-b").Should().Be(second);
    }

    [Fact]
    public void Absent_cookie_reads_nothing()
    {
        Binding().Read(new DefaultHttpContext(), "interaction-a").Should().BeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-separator")]
    [InlineData(".secret-without-issue-time")]
    [InlineData("1757160000.")]
    [InlineData("1757160000..")]
    [InlineData("1757160000.secret")]
    [InlineData("1757160000.secret.hint.extra")]
    [InlineData("not-a-number.secret.")]
    public void Cookie_that_is_not_in_the_written_form_reads_nothing(string value)
    {
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}interaction-a={value}";

        Binding().Read(read, "interaction-a").Should().BeNull();
    }

    [Fact]
    public void Cookie_outlives_its_interaction_by_the_retention_period()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", Now.AddMinutes(7), InteractionBindingCookie.NewSecret(), clientId: null);

        var expected = (int)(TimeSpan.FromMinutes(7) + InteractionBindingCookie.RetainedFor).TotalSeconds;
        write.Response.Headers.SetCookie.ToString().Should().Contain($"max-age={expected}");
    }

    [Fact]
    public void Cookie_is_HttpOnly_Secure_Lax_and_rooted()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), clientId: null);

        var setCookie = write.Response.Headers.SetCookie.ToString();
        setCookie.Should().Contain("httponly")
            .And.Contain("secure")
            .And.Contain("samesite=lax")
            .And.Contain("path=/");
    }

    [Fact]
    public void Retiring_a_binding_that_names_no_client_clears_the_cookie_for_that_interaction_only()
    {
        var binding = Binding();
        var retire = new DefaultHttpContext();

        binding.Retire(retire, "interaction-a");

        var setCookie = retire.Response.Headers.SetCookie.ToString();
        setCookie.Should().StartWith(InteractionBindingCookie.NamePrefix + "interaction-a=")
            .And.Contain("expires=Thu, 01 Jan 1970");
    }

    // ── Client hint ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Issued_client_reads_back_from_the_cookie_it_was_written_to()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a");

        binding.ReadClientId(RequestCarrying(write), "interaction-a").Should().Be("client-a");
    }

    [Fact]
    public void The_client_is_not_readable_from_the_cookie_in_plain_text()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a");

        write.Response.Headers.SetCookie.ToString().Should().NotContain("client-a");
    }

    [Fact]
    public void A_binding_issued_without_a_client_names_none()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), clientId: null);

        binding.ReadClientId(RequestCarrying(write), "interaction-a").Should().BeNull();
    }

    [Fact]
    public void A_retired_binding_keeps_its_client_and_loses_its_secret()
    {
        // What lets a page submitted after completion still send the user back to the client,
        // while nothing can address the completed interaction again.
        var binding = Binding();
        var issue = new DefaultHttpContext();
        binding.Issue(issue, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a");
        var retire = RequestCarrying(issue);

        binding.Retire(retire, "interaction-a");

        var afterwards = RequestCarrying(retire);
        binding.Read(afterwards, "interaction-a").Should().BeNull();
        binding.ReadClientId(afterwards, "interaction-a").Should().Be("client-a");
    }

    [Fact]
    public void A_retired_binding_lasts_for_the_retention_period()
    {
        var binding = Binding();
        var issue = new DefaultHttpContext();
        binding.Issue(issue, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a");
        var retire = RequestCarrying(issue);

        binding.Retire(retire, "interaction-a");

        retire.Response.Headers.SetCookie.ToString()
            .Should().Contain($"max-age={(int)InteractionBindingCookie.RetainedFor.TotalSeconds}");
    }

    [Fact]
    public void A_binding_retired_in_the_request_that_issued_it_keeps_its_client()
    {
        // prompt=none with no session stores and ends an interaction before the browser has the cookie.
        var binding = Binding();
        var context = new DefaultHttpContext();
        binding.Issue(context, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a");

        binding.Retire(context, "interaction-a");

        binding.ReadClientId(new DefaultHttpContext { Request = { Headers = { Cookie = LastSetCookie(context) } } }, "interaction-a")
            .Should().Be("client-a");
    }

    [Fact]
    public void A_client_hint_moved_into_another_interactions_cookie_reads_nothing()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();
        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a");
        var value = LastSetCookie(write)[(InteractionBindingCookie.NamePrefix + "interaction-a=").Length..];

        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}interaction-b={value}";

        binding.ReadClientId(read, "interaction-b").Should().BeNull();
    }

    [Fact]
    public void A_tampered_client_hint_reads_nothing_and_does_not_throw()
    {
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}interaction-a={Now.ToUnixTimeSeconds()}..dGFtcGVyZWQ";

        Binding().ReadClientId(read, "interaction-a").Should().BeNull();
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static readonly EphemeralDataProtectionProvider Keys = new();

    private static InteractionBindingCookie Binding() => new(new FakeTimeProvider(Now), Keys);

    private static string LastSetCookie(HttpContext written) =>
        written.Response.Headers.SetCookie[^1]!.Split(';')[0];

    /// <summary>Re-presents every Set-Cookie value as a request Cookie header, the way a browser would.</summary>
    private static DefaultHttpContext RequestCarrying(HttpContext written)
    {
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = string.Join("; ", written.Response.Headers.SetCookie.Select(header => header!.Split(';')[0]));
        return read;
    }

    private static string[] DeletedCookieNames(HttpContext context) =>
        [.. context.Response.Headers.SetCookie
            .Select(header => header ?? string.Empty)
            .Where(header => header.Contains("expires=Thu, 01 Jan 1970", StringComparison.Ordinal))
            .Select(header => header[..header.IndexOf('=')])];
}
