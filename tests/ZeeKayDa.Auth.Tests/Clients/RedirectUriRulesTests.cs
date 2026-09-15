namespace ZeeKayDa.Auth.Clients;

public sealed class RedirectUriRulesTests
{
    // ── HasIpv6ZoneId ─────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://[::1]/callback", false)]
    [InlineData("https://example.com/callback", false)]
    [InlineData("https://example.com/callback?a=[b%25c]", false)] // % in query, not authority
    [InlineData("https://[::1%25eth0]/callback", true)]      // percent-encoded zone ID
    [InlineData("https://[::1%eth0]/callback", true)]      // literal % zone ID
    [InlineData("myapp:/callback", false)]      // no "://"
    [InlineData("https://a]%25b[/cb", false)]   // ']' before '[': malformed, fails closed, never throws
    public void HasIpv6ZoneId_returns_expected_value(string uriString, bool expected)
        => RedirectUriRules.HasIpv6ZoneId(uriString).Should().Be(expected);

    // ── IsLoopbackHost ────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("localhost", true)]
    [InlineData("LOCALHOST", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("[::1]", true)]  // IPv6 brackets stripped before parse
    [InlineData("192.168.1.1", false)]
    [InlineData("example.com", false)]
    public void IsLoopbackHost_returns_expected_value(string host, bool expected)
        => RedirectUriRules.IsLoopbackHost(host).Should().Be(expected);

    // ── IsSchemeAllowed ───────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://example.com/cb", true)]
    [InlineData("http://127.0.0.1/cb", true)]   // http + loopback
    [InlineData("com.example.app:/callback", true)]   // dot in scheme
    [InlineData("http://example.com/cb", false)]  // http non-loopback
    [InlineData("ftp://example.com/cb", false)]
    [InlineData("myapp:/callback", false)]  // no dot in scheme
    public void IsSchemeAllowed_returns_expected_value(string input, bool expected)
    {
        Uri.TryCreate(input, UriKind.Absolute, out var uri).Should().BeTrue();
        RedirectUriRules.IsSchemeAllowed(uri!).Should().Be(expected);
    }

    // ── HasPathTraversal ──────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://example.com/callback", false)]
    [InlineData("https://example.com/a/b/callback", false)]
    [InlineData("https://example.com/..foo/bar", false)] // not exactly ".."
    [InlineData("https://example.com/callback/..", true)]
    [InlineData("https://example.com/callback/../other", true)]
    [InlineData("https://example.com/callback/..?query=1", true)]  // truncated at "?"
    [InlineData("https://example.com/callback/%2E%2E", true)]  // percent-encoded
    [InlineData("https://example.com/callback/.%2e", true)]  // mixed encoding
    [InlineData("com.example.app:/callback/../other", true)]  // private-use single-slash
    [InlineData("myapp:/callback", false)] // no path after ":/"
    [InlineData("https://example.com/callback/./other", true)]  // single-dot segment
    [InlineData("https://example.com/callback/%2E/other", true)]  // percent-encoded single dot
    [InlineData("https:///..", true)]  // empty authority still yields a path to inspect
    [InlineData("urn:example:animal", false)]  // neither "://" nor ":/" — no path form at all
    public void HasPathTraversal_returns_expected_value(string uriString, bool expected)
        => RedirectUriRules.HasPathTraversal(uriString).Should().Be(expected);

    // ── HasFragment ───────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://example.com/callback", false)]
    [InlineData("https://example.com/callback?a=1", false)]
    [InlineData("https://example.com/callback#frag", true)]
    [InlineData("com.example.app:/callback#frag", true)]
    public void HasFragment_returns_expected_value(string input, bool expected)
        => RedirectUriRules.HasFragment(new Uri(input)).Should().Be(expected);

    // ── HasUserInfo ───────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://example.com/callback", false)]
    [InlineData("https://user@example.com/callback", true)]
    [InlineData("https://user:pass@example.com/callback", true)]
    public void HasUserInfo_returns_expected_value(string input, bool expected)
        => RedirectUriRules.HasUserInfo(new Uri(input)).Should().Be(expected);

    // ── IsHttp ────────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://example.com/cb", true)]
    [InlineData("HTTP://example.com/cb", true)]
    [InlineData("https://example.com/cb", false)]
    [InlineData("com.example.app:/callback", false)]
    public void IsHttp_returns_expected_value(string input, bool expected)
        => RedirectUriRules.IsHttp(new Uri(input)).Should().Be(expected);

    // ── IsHttpLocalhost ───────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://localhost/cb", true)]
    [InlineData("HTTP://LOCALHOST:5001/cb", true)]   // case-insensitive scheme and host
    [InlineData("https://localhost:5001/cb", false)] // web client on a dev certificate, not a loopback redirect
    [InlineData("http://127.0.0.1/cb", false)]       // loopback, but not the name 'localhost'
    [InlineData("http://localhost.example.com/cb", false)]
    [InlineData("not a uri", false)]                 // does not parse
    [InlineData("/relative/path", false)]            // not absolute
    public void IsHttpLocalhost_returns_expected_value(string uriString, bool expected)
        => RedirectUriRules.IsHttpLocalhost(uriString).Should().Be(expected);
}
