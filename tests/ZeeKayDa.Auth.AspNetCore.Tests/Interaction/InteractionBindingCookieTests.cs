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
        binding.Issue(write, new("interaction-a", ExpiresAt, secret, null));

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

        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

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
        binding.Issue(write, new("interaction-a", ExpiresAt, first, null));
        binding.Issue(write, new("interaction-b", ExpiresAt, second, null));

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
    public void A_cookie_that_names_no_client_expires_with_its_interaction()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, new("interaction-a", Now.AddMinutes(7), InteractionBindingCookie.NewSecret(), null));

        write.Response.Headers.SetCookie.ToString().Should().Contain("max-age=420");
    }

    [Fact]
    public void A_cookie_that_names_a_client_outlives_its_interaction_by_the_retention_period()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, new("interaction-a", Now.AddMinutes(7), InteractionBindingCookie.NewSecret(), "client-a"));

        var expected = (int)(TimeSpan.FromMinutes(7) + InteractionBindingCookie.RetainedFor).TotalSeconds;
        write.Response.Headers.SetCookie.ToString().Should().Contain($"max-age={expected}");
    }

    [Fact]
    public void Cookie_is_HttpOnly_Secure_Lax_and_rooted()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

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

        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));

        binding.ReadClientId(RequestCarrying(write), "interaction-a").Should().Be("client-a");
    }

    [Fact]
    public void The_client_is_not_readable_from_the_cookie_in_plain_text()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));

        write.Response.Headers.SetCookie.ToString().Should().NotContain("client-a");
    }

    [Fact]
    public void A_binding_issued_without_a_client_names_none()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();

        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

        binding.ReadClientId(RequestCarrying(write), "interaction-a").Should().BeNull();
    }

    [Fact]
    public void A_retired_binding_keeps_its_client_and_loses_its_secret()
    {
        // What lets a page submitted after completion still send the user back to the client,
        // while nothing can address the completed interaction again.
        var binding = Binding();
        var issue = new DefaultHttpContext();
        binding.Issue(issue, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));
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
        binding.Issue(issue, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));
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
        binding.Issue(context, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));

        binding.Retire(context, "interaction-a");

        binding.ReadClientId(new DefaultHttpContext { Request = { Headers = { Cookie = LastSetCookie(context) } } }, "interaction-a")
            .Should().Be("client-a");
    }

    [Fact]
    public void A_client_hint_moved_into_another_interactions_cookie_reads_nothing()
    {
        var binding = Binding();
        var write = new DefaultHttpContext();
        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));
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

    [Fact]
    public void Issuing_at_the_cap_evicts_the_oldest_binding_first()
    {
        // A run of abandoned or planted requests must not grow the Cookie header without bound.
        // The eldest goes, whatever order the browser presented them in.
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}.secret.")
                .Reverse());

        binding.Issue(request, new("interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

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
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.ToUnixTimeSeconds()}.secret."));

        binding.Issue(request, new("interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

        DeletedCookieNames(request).Should().BeEmpty();
    }

    [Fact]
    public void Issuing_over_the_cap_evicts_enough_to_get_back_under_it()
    {
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser + 2)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}.secret."));

        binding.Issue(request, new("interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

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
                .Select(i => $"{InteractionBindingCookie.NamePrefix}interaction-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}.secret.")
                .Append($"{InteractionBindingCookie.NamePrefix}garbage=not-ours"));

        binding.Issue(request, new("interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

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

        binding.Issue(request, new("interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

        DeletedCookieNames(request).Should().BeEmpty();
    }

    [Fact]
    public void Retired_bindings_are_evicted_before_a_live_one_however_old()
    {
        // A live login tab must not lose its binding to sign-ins the user already finished.
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxPerBrowser - InteractionBindingCookie.MaxRetired)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}live-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}.secret.")
                .Concat(Enumerable.Range(0, InteractionBindingCookie.MaxRetired)
                    .Select(i => $"{InteractionBindingCookie.NamePrefix}retired-{i}={Now.AddMinutes(60 + i).ToUnixTimeSeconds()}..hint")));

        binding.Issue(request, new("interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

        DeletedCookieNames(request).Should().Equal(InteractionBindingCookie.NamePrefix + "retired-0");
    }

    [Fact]
    public void Issuing_keeps_no_more_than_the_retired_maximum()
    {
        var binding = Binding();
        var request = new DefaultHttpContext();
        request.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxRetired + 2)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}retired-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}..hint"));

        binding.Issue(request, new("interaction-new", ExpiresAt, InteractionBindingCookie.NewSecret(), null));

        DeletedCookieNames(request).Should().Equal(
            InteractionBindingCookie.NamePrefix + "retired-0",
            InteractionBindingCookie.NamePrefix + "retired-1");
    }

    [Fact]
    public void Retiring_makes_room_among_the_retired_bindings_and_leaves_live_ones_alone()
    {
        var binding = Binding();
        var issue = new DefaultHttpContext();
        binding.Issue(issue, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));
        var retire = new DefaultHttpContext();
        retire.Request.Headers.Cookie = string.Join("; ",
            Enumerable.Range(0, InteractionBindingCookie.MaxRetired)
                .Select(i => $"{InteractionBindingCookie.NamePrefix}retired-{i}={Now.AddMinutes(i).ToUnixTimeSeconds()}..hint")
                .Append($"{InteractionBindingCookie.NamePrefix}live={Now.ToUnixTimeSeconds()}.secret.")
                .Append(LastSetCookie(issue)));

        binding.Retire(retire, "interaction-a");

        DeletedCookieNames(retire).Should().Equal(InteractionBindingCookie.NamePrefix + "retired-0");
    }

    [Fact]
    public void A_client_hint_past_its_lifetime_reads_nothing()
    {
        // Judged on the framework's clock: a value replayed by hand after the browser dropped the
        // cookie names no client.
        var time = new FakeTimeProvider(Now);
        var binding = new InteractionBindingCookie(time, Keys);
        var write = new DefaultHttpContext();
        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));

        time.Advance(ExpiresAt - Now + InteractionBindingCookie.RetainedFor);

        binding.ReadClientId(RequestCarrying(write), "interaction-a").Should().BeNull();
    }

    [Fact]
    public void A_client_hint_within_its_lifetime_reads_its_client()
    {
        var time = new FakeTimeProvider(Now);
        var binding = new InteractionBindingCookie(time, Keys);
        var write = new DefaultHttpContext();
        binding.Issue(write, new("interaction-a", ExpiresAt, InteractionBindingCookie.NewSecret(), "client-a"));

        time.Advance(ExpiresAt - Now + InteractionBindingCookie.RetainedFor - TimeSpan.FromSeconds(1));

        binding.ReadClientId(RequestCarrying(write), "interaction-a").Should().Be("client-a");
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
