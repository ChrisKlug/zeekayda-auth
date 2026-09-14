namespace ZeeKayDa.Auth.Configuration;

public sealed class ServerUriRulesTests
{
    // ── IsSchemePermitted ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://auth.example.com", false, true)]
    [InlineData("HTTPS://auth.example.com", false, true)]
    [InlineData("http://localhost", false, false)]         // HTTP needs AllowInsecureIssuer
    [InlineData("http://localhost", true, true)]
    [InlineData("http://auth.example.com", true, true)]    // scheme is permitted; the loopback rule is separate
    [InlineData("ftp://auth.example.com", true, false)]
    public void IsSchemePermitted_returns_expected_value(string input, bool allowInsecure, bool expected)
        => ServerUriRules.IsSchemePermitted(new Uri(input), allowInsecure).Should().Be(expected);

    // ── IsInsecureNonLoopback ─────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://auth.example.com", true, true)]
    [InlineData("http://127.0.0.1", true, false)]
    [InlineData("http://localhost", true, false)]
    [InlineData("http://auth.example.com", false, false)]  // not admitted at all, so not this rule
    [InlineData("https://auth.example.com", true, false)]
    public void IsInsecureNonLoopback_returns_expected_value(string input, bool allowInsecure, bool expected)
        => ServerUriRules.IsInsecureNonLoopback(new Uri(input), allowInsecure).Should().Be(expected);
}
