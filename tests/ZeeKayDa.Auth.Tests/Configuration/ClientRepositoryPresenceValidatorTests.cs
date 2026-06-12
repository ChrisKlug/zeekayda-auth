using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class ClientRepositoryPresenceValidatorTests
{
    private static AuthorizationServerOptions DefaultOptions()
        => new() { Issuer = "https://auth.example.com" };

    private sealed class FakeIsService : IServiceProviderIsService
    {
        private readonly bool _result;
        public FakeIsService(bool result) => _result = result;
        public bool IsService(Type serviceType) => _result;
    }

    [Fact]
    public void Validate_WhenIsServiceIsNull_ReturnsSuccess()
    {
        var validator = new ClientRepositoryPresenceValidator(null);

        var result = validator.Validate(null, DefaultOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_WhenIClientRepositoryNotRegistered_ReturnsFail()
    {
        var validator = new ClientRepositoryPresenceValidator(new FakeIsService(false));

        var result = validator.Validate(null, DefaultOptions());

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("IClientRepository");
    }

    [Fact]
    public void Validate_WhenIClientRepositoryIsRegistered_ReturnsSuccess()
    {
        var validator = new ClientRepositoryPresenceValidator(new FakeIsService(true));

        var result = validator.Validate(null, DefaultOptions());

        result.Succeeded.Should().BeTrue();
    }
}
