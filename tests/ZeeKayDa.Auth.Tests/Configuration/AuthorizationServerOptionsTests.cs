namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class AuthorizationServerOptionsTests
{
    // ── Default property values ───────────────────────────────────────────────────────────────────

    [Fact]
    public void AllowInMemoryStoresOutsideDevelopment_defaults_to_false()
    {
        var options = new AuthorizationServerOptions();

        options.AllowInMemoryStoresOutsideDevelopment.Should().BeFalse();
    }

    [Fact]
    public void AllowInMemoryStoresOutsideDevelopment_can_be_set_to_true()
    {
        var options = new AuthorizationServerOptions
        {
            AllowInMemoryStoresOutsideDevelopment = true,
        };

        options.AllowInMemoryStoresOutsideDevelopment.Should().BeTrue();
    }
}
