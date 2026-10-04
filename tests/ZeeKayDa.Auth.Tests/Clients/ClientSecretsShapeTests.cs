using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
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
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<ClientSecrets>();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<ClientSecrets>().Create("a-client-secret").Value
            .Should().StartWith("$pbkdf2-sha256$", "the framework's instance resolves and hashes");
    }

    [Fact]
    public void Calling_AddZeeKayDaAuthCore_twice_registers_ClientSecrets_once()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");

        services.Count(descriptor => descriptor.ServiceType == typeof(ClientSecrets)).Should().Be(1);
    }
}
