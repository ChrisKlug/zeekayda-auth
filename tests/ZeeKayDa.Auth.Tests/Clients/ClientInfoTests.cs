using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientInfoTests
{
    [Fact]
    public void IClientInfo_does_not_expose_credentials()
    {
        // The point of the split: code that only decides what to issue a client never sees its
        // secrets. Moving Credentials up to IClientInfo would silently undo that.
        typeof(IClientInfo).GetProperty(nameof(IClientRegistration.Credentials))
            .Should().BeNull();
    }

    [Fact]
    public void IClientRegistration_is_an_IClientInfo()
    {
        typeof(IClientInfo).IsAssignableFrom(typeof(IClientRegistration)).Should().BeTrue();
    }
}
