using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientSecretHasherActivatorTests
{
    [Fact]
    public async Task A_hasher_that_cannot_be_built_is_reported_against_this_check_while_the_other_activators_still_run()
    {
        var otherActivatorRan = false;
        var services = new ServiceCollection();
        services.AddSingleton<CompositeClientSecretHasher>(_ => throw new InvalidOperationException("no decoy"));
        services.AddScoped<IStartupActivator, ClientSecretHasherActivator>();
        services.AddScoped<IStartupActivator>(_ => new RecordingActivator(() => otherActivatorRan = true));
        using var provider = services.BuildServiceProvider();
        var sut = new StartupVerificationHostedService(
            provider.GetRequiredService<IServiceScopeFactory>(), new ServiceLifetimeScanner(services));

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var failure = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle().Subject;
        failure.Message.Should().Contain("ClientSecretHasherActivation");
        otherActivatorRan.Should().BeTrue();
    }

    private sealed class RecordingActivator(Action onVerify) : IStartupActivator
    {
        public string Name => "Recording";

        public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
        {
            onVerify();
            return Task.CompletedTask;
        }
    }
}
