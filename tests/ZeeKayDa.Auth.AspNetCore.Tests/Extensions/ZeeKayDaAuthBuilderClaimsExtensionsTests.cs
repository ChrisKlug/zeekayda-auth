using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderClaimsExtensionsTests
{
    [Fact]
    public void AddClaimsProvider_registers_the_provider_scoped_so_it_can_take_a_per_request_context()
    {
        var services = new ServiceCollection();

        new ZeeKayDaAuthBuilder(services).AddClaimsProvider<NoClaimsProvider>();

        var descriptor = services.Should().ContainSingle(d => d.ServiceType == typeof(IClaimsProvider)).Subject;
        descriptor.ImplementationType.Should().Be(typeof(NoClaimsProvider));
        descriptor.Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void A_later_registration_replaces_an_earlier_one()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddClaimsProvider<NoClaimsProvider>().AddClaimsProvider<OtherClaimsProvider>();

        services.Should().ContainSingle(d => d.ServiceType == typeof(IClaimsProvider))
            .Which.ImplementationType.Should().Be(typeof(OtherClaimsProvider));
    }

    [Fact]
    public void AddClaimsProvider_returns_the_builder_for_chaining()
    {
        var builder = new ZeeKayDaAuthBuilder(new ServiceCollection());

        builder.AddClaimsProvider<NoClaimsProvider>().Should().BeSameAs(builder);
    }

    private sealed class OtherClaimsProvider : IClaimsProvider
    {
        public ValueTask<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ClaimsResolutionResult>(new ClaimsResolutionResult.SubjectInvalid());
    }
}
