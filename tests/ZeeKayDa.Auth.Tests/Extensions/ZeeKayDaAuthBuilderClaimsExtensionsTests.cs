using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderClaimsExtensionsTests
{
    [Fact]
    public void AddClaimsProvider_registers_the_provider_scoped_so_it_can_take_a_per_request_context()
    {
        var services = new ServiceCollection();

        new ZeeKayDaAuthCoreBuilder(services).AddClaimsProvider<NoClaimsProvider>();

        var descriptor = services.Should().ContainSingle(d => d.ServiceType == typeof(IClaimsProvider)).Subject;
        descriptor.ImplementationType.Should().Be(typeof(NoClaimsProvider));
        descriptor.Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void A_later_registration_replaces_an_earlier_one()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddClaimsProvider<NoClaimsProvider>().AddClaimsProvider<OtherClaimsProvider>();

        services.Should().ContainSingle(d => d.ServiceType == typeof(IClaimsProvider))
            .Which.ImplementationType.Should().Be(typeof(OtherClaimsProvider));
    }

    [Fact]
    public void AddZeeKayDaAuth_registers_the_presence_check_as_an_activator_not_a_verifier()
    {
        // The check may resolve the caller's scoped provider on a container without
        // IServiceProviderIsService, and only the activator phase may touch caller-supplied code.
        var services = new ServiceCollection();

        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://test.example.com");

        services.Should().ContainSingle(d => d.ImplementationType == typeof(ClaimsProviderPresenceActivator))
            .Which.ServiceType.Should().Be(typeof(IStartupActivator));
    }

    [Fact]
    public void AddClaimsProvider_returns_the_builder_for_chaining()
    {
        var builder = new ZeeKayDaAuthCoreBuilder(new ServiceCollection());

        builder.AddClaimsProvider<NoClaimsProvider>().Should().BeSameAs(builder);
    }

    private sealed class OtherClaimsProvider : IClaimsProvider
    {
        public Task<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<ClaimsResolutionResult>(new ClaimsResolutionResult.SubjectInvalid());
    }
}
