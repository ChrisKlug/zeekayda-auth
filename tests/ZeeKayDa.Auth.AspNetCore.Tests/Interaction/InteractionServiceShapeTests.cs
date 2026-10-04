using System.Reflection;
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

    [Fact]
    public void Every_public_interaction_service_is_covered()
    {
        typeof(LoginInteraction).Assembly.GetExportedTypes()
            .Where(type => type.Namespace == typeof(LoginInteraction).Namespace && type.Name.EndsWith("Interaction", StringComparison.Ordinal))
            .Should().BeEquivalentTo(InteractionServices().Select(row => row.Data));
    }
}
