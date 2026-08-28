using ZeeKayDa.Auth.Security;

namespace ZeeKayDa.Auth.Tests.Security;

public sealed class SecurityHeadersOptionsTests
{
    [Fact]
    public void ContentTypeOptionsNoSniff_is_enabled_by_default()
    {
        // Security-control default: nosniff must be on unless an operator explicitly turns it
        // off. A flipped default silently drops the header from every protocol response.
        new SecurityHeadersOptions().ContentTypeOptionsNoSniff.Should().BeTrue();
    }
}
