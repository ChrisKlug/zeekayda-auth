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
        binding.Issue(write, "interaction-a", ExpiresAt, secret);

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

        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret());

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
        binding.Issue(write, "interaction-a", ExpiresAt, first);
        binding.Issue(write, "interaction-b", ExpiresAt, second);

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
    [InlineData("not-a-number.secret")]
    public void Cookie_that_is_not_in_the_written_form_reads_nothing(string value)
    {
        var read = new DefaultHttpContext();
        read.Request.Headers.Cookie = $"{InteractionBindingCookie.NamePrefix}interaction-a={value}";

        Binding().Read(read, "interaction-a").Should().BeNull();
    }

    [Fact]
    public void Cookie_expires_with_its_interaction()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", Now.AddMinutes(7), InteractionBindingCookie.NewSecret());

        write.Response.Headers.SetCookie.ToString().Should().Contain("max-age=420");
    }

    [Fact]
    public void Cookie_is_HttpOnly_Secure_Lax_and_rooted()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, "interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret());

        var setCookie = write.Response.Headers.SetCookie.ToString();
        setCookie.Should().Contain("httponly")
            .And.Contain("secure")
            .And.Contain("samesite=lax")
            .And.Contain("path=/");
    }

    [Fact]
    public void Deleting_clears_the_cookie_for_that_interaction_only()
    {
        var binding = Binding();
        var delete = new DefaultHttpContext();

        binding.Delete(delete, "interaction-a");

        var setCookie = delete.Response.Headers.SetCookie.ToString();
        setCookie.Should().StartWith(InteractionBindingCookie.NamePrefix + "interaction-a=")
            .And.Contain("expires=Thu, 01 Jan 1970");
    }

    [Fact]
    public void Issuing_at_the_cap_evicts_the_oldest_binding_first()
    {
        // A run of abandoned or planted requests must not grow the Cookie header without bound.
        // The eldest goes, whatever order the browser presented them in.
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}.secret")
                .Reverse());

        binding.Issue(request, "interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret());

        var deleted = DeletedCookieNames(request);
        deleted.Should().Equal(InteractionBindingCookie.NamePrefix + "interaction-0");
    }

    [Fact]
    public void Issuing_below_the_cap_evicts_nothing()
    {
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser - 1)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.ToUnixTimeSeconds()}.secret"));

        binding.Issue(request, "interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret());

        DeletedCookieNames(request).Should().BeEmpty();
    }

    [Fact]
    public void Issuing_over_the_cap_evicts_enough_to_get_back_under_it()
    {
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser + 2)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}.secret"));

        binding.Issue(request, "interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret());

        DeletedCookieNames(request).Should().Equal(
            InteractionBindingCookie.NamePrefix + "interaction-0",
            InteractionBindingCookie.NamePrefix + "interaction-1",
            InteractionBindingCookie.NamePrefix + "interaction-2");
    }

    [Fact]
    public void A_binding_that_does_not_parse_is_evicted_before_any_that_does()
    {
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser - 1)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}.secret")
                .Append($"{InteractionBindingCookie.NamePrefix}garbage=not-ours"));

        binding.Issue(request, "interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret());

        DeletedCookieNames(request).Should().Equal(InteractionBindingCookie.NamePrefix + "garbage");
    }

    [Fact]
    public void Other_cookies_never_count_towards_the_cap()
    {
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser)
                .Select(i => $"host.cookie{i}=value")
                .Append($"{ZeeKayDaCookies.Interaction}=not-a-binding")
                .Append($"{ZeeKayDaCookies.Session}=session"));

        binding.Issue(request, "interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret());

        DeletedCookieNames(request).Should().BeEmpty();
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static InteractionBindingCookie Binding() => new(new FakeTimeProvider(Now));

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
