using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

public sealed class InteractionServiceShapeTests
{
    public static TheoryData<Type> InteractionServices() =>
    [
        typeof(LoginInteraction),
        typeof(ConsentInteraction),
        typeof(ErrorInteraction),
        typeof(LogoutInteraction),
        typeof(ProviderSignInInteraction),
    ];

    [Theory]
    [MemberData(nameof(InteractionServices))]
    public void An_interaction_service_cannot_be_supplied_by_a_host(Type service)
    {
        service.IsSealed.Should().BeTrue("a host must not derive its own");
        service.GetConstructors(BindingFlags.Public | BindingFlags.Instance)
            .Should().BeEmpty("a host must not construct its own");
    }

    [Theory]
    [MemberData(nameof(InteractionServices))]
    public void A_host_registration_made_before_AddZeeKayDaAuth_does_not_displace_the_frameworks(Type service)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(service);
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com")
            .AddInMemoryStores(allowOutsideDevelopment: true);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService(service).Should().BeOfType(service, "the framework's instance resolves");
    }

    [Theory]
    [MemberData(nameof(InteractionServices))]
    public void Calling_AddZeeKayDaAuth_twice_registers_each_interaction_service_once(Type service)
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Count(descriptor => descriptor.ServiceType == service).Should().Be(1);
    }

    [Fact]
    public void Every_public_interaction_service_is_covered()
    {
        typeof(LoginInteraction).Assembly.GetExportedTypes()
            .Where(type => type.Namespace == typeof(LoginInteraction).Namespace && type.Name.EndsWith("Interaction", StringComparison.Ordinal))
            .Should().BeEquivalentTo(InteractionServices().Select(row => row.Data));
    }
}
