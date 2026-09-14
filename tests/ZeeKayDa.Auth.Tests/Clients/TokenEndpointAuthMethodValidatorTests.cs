namespace ZeeKayDa.Auth.Clients;

public sealed class TokenEndpointAuthMethodValidatorTests
{
    // ── AllowsNone ────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(true, "none")]
    [InlineData(true, "none", "client_secret_basic")]  // mixed set
    [InlineData(false, "client_secret_basic")]
    [InlineData(false, "None")]                        // ordinal, not case-insensitive
    [InlineData(false, " none")]                       // no trimming
    [InlineData(false)]                                // empty
    public void AllowsNone_returns_expected_value(bool expected, params string[] methods)
        => TokenEndpointAuthMethodValidator.AllowsNone(methods).Should().Be(expected);
}
