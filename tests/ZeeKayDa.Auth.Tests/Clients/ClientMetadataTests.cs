using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientMetadataTests
{
    [Fact]
    public void IClientMetadata_does_not_expose_credentials()
    {
        // The point of the split: code that only decides what to issue a client never sees its
        // secrets. Moving Credentials up to IClientMetadata would silently undo that.
        typeof(IClientMetadata).GetProperty(nameof(IClientRegistration.Credentials))
            .Should().BeNull();
    }

    [Fact]
    public void IClientRegistration_is_an_IClientMetadata()
    {
        typeof(IClientMetadata).IsAssignableFrom(typeof(IClientRegistration)).Should().BeTrue();
    }
}
