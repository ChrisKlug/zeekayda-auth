using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientSecretsShapeTests
{
    [Fact]
    public void ClientSecrets_cannot_be_supplied_by_a_host()
    {
        typeof(ClientSecrets).IsSealed.Should().BeTrue("a host must not derive its own");
        typeof(ClientSecrets).GetConstructors(BindingFlags.Public | BindingFlags.Instance)
            .Should().BeEmpty("a host must not construct its own");
    }

    [Fact]
    public void A_host_registration_made_before_AddZeeKayDaAuthCore_does_not_displace_the_frameworks()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ClientSecrets>();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");

        // The container resolves the last registration of a type: it must be the framework's factory.
        services.Last(descriptor => descriptor.ServiceType == typeof(ClientSecrets))
            .ImplementationFactory.Should().NotBeNull("the framework builds it through a factory");
    }
}
