namespace ZeeKayDa.Auth.Tokens;

public sealed class TokenEndpointAuthMethodRulesTests
{
    // ── IsBlank ───────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("   ", true)]
    [InlineData("client_secret_basic", false)]
    public void IsBlank_returns_expected_value(string? method, bool expected)
        => TokenEndpointAuthMethodRules.IsBlank(method).Should().Be(expected);

    // ── HasSurroundingWhitespace ──────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("client_secret_basic", false)]
    [InlineData(" client_secret_basic", true)]
    [InlineData("client_secret_basic ", true)]
    [InlineData("client_secret_basic\t", true)]
    public void HasSurroundingWhitespace_returns_expected_value(string method, bool expected)
        => TokenEndpointAuthMethodRules.HasSurroundingWhitespace(method).Should().Be(expected);

    // ── HasControlCharacters ──────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("client_secret_basic", false)]
    [InlineData("client\u0000secret", true)]
    [InlineData("client_secret\u0007basic", true)]
    public void HasControlCharacters_returns_expected_value(string method, bool expected)
        => TokenEndpointAuthMethodRules.HasControlCharacters(method).Should().Be(expected);

    // ── IsWellFormed ──────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("client_secret_basic", true)]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]        // blank, and also untrimmed: one rule is enough
    [InlineData(" none", false)]
    [InlineData("no\u0007ne", false)]
    public void IsWellFormed_returns_expected_value(string? method, bool expected)
        => TokenEndpointAuthMethodRules.IsWellFormed(method).Should().Be(expected);

    // ── AllowsNone ────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(true, "none")]
    [InlineData(true, "none", "client_secret_basic")]  // mixed set
    [InlineData(false, "client_secret_basic")]
    [InlineData(false, "None")]                        // ordinal, not case-insensitive
    [InlineData(false, " none")]                       // no trimming
    [InlineData(false)]                                // empty
    public void AllowsNone_returns_expected_value(bool expected, params string[] methods)
        => TokenEndpointAuthMethodRules.AllowsNone(methods).Should().Be(expected);

    // ── AllowsOnlyNone ────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(true, "none")]
    [InlineData(false, "none", "client_secret_basic")]  // mixed set
    [InlineData(false, "client_secret_basic")]
    [InlineData(false, "None")]                         // ordinal, not case-insensitive
    [InlineData(true)]                                  // vacuously true; callers check emptiness first
    public void AllowsOnlyNone_returns_expected_value(bool expected, params string[] methods)
        => TokenEndpointAuthMethodRules.AllowsOnlyNone(methods).Should().Be(expected);
}
