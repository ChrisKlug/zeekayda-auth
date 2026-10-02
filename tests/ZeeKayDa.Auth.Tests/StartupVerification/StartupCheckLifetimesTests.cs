using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.StartupVerification;

public sealed class StartupCheckLifetimesTests
{
    [Fact]
    public void A_verifier_registered_as_a_singleton_fails_startup_naming_its_type()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier, ProbeVerifier>();

        var failure = Failures(services).Should().ContainSingle().Subject;

        failure.Code.Should().Be("startup.check_not_scoped");
        failure.Message.Should().Contain(typeof(ProbeVerifier).FullName!).And.Contain("Singleton");
    }

    [Fact]
    public void An_activator_registered_as_transient_fails_startup()
    {
        var services = new ServiceCollection();
        services.AddTransient<IStartupActivator, ProbeActivator>();

        Failures(services).Should().ContainSingle()
            .Which.Message.Should().Contain(typeof(ProbeActivator).FullName!).And.Contain("Transient");
    }

    [Fact]
    public void A_singleton_instance_registration_is_named_by_the_instances_type()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(new ProbeVerifier());

        Failures(services).Should().ContainSingle()
            .Which.Message.Should().Contain(typeof(ProbeVerifier).FullName!);
    }

    [Fact]
    public void Scoped_checks_pass()
    {
        var services = new ServiceCollection();
        services.AddScoped<IStartupVerifier, ProbeVerifier>();
        services.AddScoped<IStartupActivator>(_ => new ProbeActivator());

        Failures(services).Should().BeEmpty();
    }

    [Fact]
    public void A_keyed_registration_is_ignored_because_the_runner_never_enumerates_it()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IStartupVerifier, ProbeVerifier>("elsewhere");

        Failures(services).Should().BeEmpty();
    }

    [Fact]
    public void Every_check_the_framework_registers_is_scoped()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://issuer.test")
            .AddInMemoryStores();

        Failures(services).Should().BeEmpty();
    }

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Failures(IServiceCollection services)
    {
        try
        {
            StartupCheckLifetimes.ThrowIfAnyNotScoped(new ServiceLifetimeScanner(services));
            return [];
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            return ex.AggregatedFailures;
        }
    }

    private sealed class ProbeVerifier : IStartupVerifier
    {
        public string Name => "Probe";

        public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class ProbeActivator : IStartupActivator
    {
        public string Name => "Probe";

        public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
