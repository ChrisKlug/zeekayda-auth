using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.StartupVerification;

public sealed class StartupCheckLifetimeVerifierTests
{
    [Fact]
    public async Task A_verifier_registered_as_a_singleton_fails_startup_naming_its_type()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier, ProbeVerifier>();

        var failure = (await VerifyAsync(services)).Failures.Should().ContainSingle().Subject;

        failure.Code.Should().Be("startup.check_not_scoped");
        failure.Message.Should().Contain(typeof(ProbeVerifier).FullName!).And.Contain("Singleton");
    }

    [Fact]
    public async Task An_activator_registered_as_transient_fails_startup()
    {
        var services = new ServiceCollection();
        services.AddTransient<IStartupActivator, ProbeActivator>();

        (await VerifyAsync(services)).Failures.Should().ContainSingle()
            .Which.Message.Should().Contain(typeof(ProbeActivator).FullName!).And.Contain("Transient");
    }

    [Fact]
    public async Task A_singleton_instance_registration_is_named_by_the_instances_type()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(new ProbeVerifier());

        (await VerifyAsync(services)).Failures.Should().ContainSingle()
            .Which.Message.Should().Contain(typeof(ProbeVerifier).FullName!);
    }

    [Fact]
    public async Task Scoped_checks_pass()
    {
        var services = new ServiceCollection();
        services.AddScoped<IStartupVerifier, ProbeVerifier>();
        services.AddScoped<IStartupActivator>(_ => new ProbeActivator());

        (await VerifyAsync(services)).Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task A_keyed_registration_is_ignored_because_the_runner_never_enumerates_it()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IStartupVerifier, ProbeVerifier>("elsewhere");

        (await VerifyAsync(services)).Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task Every_check_the_framework_registers_is_scoped()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://issuer.test")
            .AddInMemoryStores();

        (await VerifyAsync(services)).Failures.Should().BeEmpty();
    }

    private static async Task<StartupVerificationContext> VerifyAsync(IServiceCollection services)
    {
        var context = new StartupVerificationContext();
        await new StartupCheckLifetimeVerifier(new ServiceLifetimeScanner(services))
            .VerifyAsync(context, TestContext.Current.CancellationToken);
        return context;
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
