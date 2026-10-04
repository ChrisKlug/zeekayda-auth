using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

public sealed class InteractionServicesRegistrationVerifierTests
{
    public static TheoryData<Type> InteractionServices() =>
        [.. InteractionServicesRegistrationVerifier.FrameworkImplementations.Keys];

    [Fact]
    public async Task The_framework_registrations_pass()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        (await FailuresFor(services)).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(InteractionServices))]
    public async Task A_host_interaction_service_registered_before_the_framework_fails_startup(Type service)
    {
        var services = new ServiceCollection();
        services.AddSingleton(service, _ => null!);
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        (await FailuresFor(services)).Should().ContainSingle()
            .Which.Code.Should().Be("interaction.service.replaced");
    }

    [Theory]
    [MemberData(nameof(InteractionServices))]
    public async Task A_host_interaction_service_registered_after_the_framework_fails_startup(Type service)
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        services.AddSingleton(service, _ => null!);

        (await FailuresFor(services)).Should().ContainSingle()
            .Which.Code.Should().Be("interaction.service.replaced");
    }

    [Theory]
    [MemberData(nameof(InteractionServices))]
    public async Task A_keyed_host_interaction_service_fails_startup(Type service)
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        services.AddKeyedSingleton(service, "custom", (_, _) => null!);

        (await FailuresFor(services)).Should().ContainSingle()
            .Which.Code.Should().Be("interaction.service.replaced");
    }

    [Fact]
    public async Task A_host_interaction_service_fails_a_real_startup()
    {
        using var host = new EndpointHost(configureBuilder: builder =>
            builder.Services.AddSingleton<ILoginInteraction>(_ => null!));

        var act = async () => await host.EnsureStartedAsync();

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(failure => failure.Code == "interaction.service.replaced");
    }

    [Fact]
    public void Every_public_interaction_interface_is_checked()
    {
        var interfaces = typeof(ILoginInteraction).Assembly.GetExportedTypes()
            .Where(type => type.IsInterface && type.Namespace == typeof(ILoginInteraction).Namespace);

        interfaces.Should().BeEquivalentTo(InteractionServicesRegistrationVerifier.FrameworkImplementations.Keys);
    }

    private static async Task<IReadOnlyList<ZeeKayDaConfigurationFailure>> FailuresFor(ServiceCollection services)
    {
        var context = new StartupVerificationContext();
        await new InteractionServicesRegistrationVerifier(new ServiceLifetimeScanner(services))
            .VerifyAsync(context, TestContext.Current.CancellationToken);
        return context.Failures;
    }
}
