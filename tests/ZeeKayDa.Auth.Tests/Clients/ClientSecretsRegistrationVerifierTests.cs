using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientSecretsRegistrationVerifierTests
{
    [Fact]
    public async Task The_framework_registration_passes()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");

        (await FailuresFor(services)).Should().BeEmpty();
    }

    [Fact]
    public async Task A_host_IClientSecrets_registered_before_the_framework_fails_startup()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IClientSecrets>(new HostClientSecrets());
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");

        (await FailuresFor(services)).Should().ContainSingle()
            .Which.Code.Should().Be("clients.secrets.replaced");
    }

    [Fact]
    public async Task A_host_IClientSecrets_registered_after_the_framework_fails_startup()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        services.AddSingleton<IClientSecrets, HostClientSecrets>();

        (await FailuresFor(services)).Should().ContainSingle()
            .Which.Code.Should().Be("clients.secrets.replaced");
    }

    [Fact]
    public async Task A_keyed_host_IClientSecrets_fails_startup()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        services.AddKeyedSingleton<IClientSecrets, HostClientSecrets>("custom");

        (await FailuresFor(services)).Should().ContainSingle()
            .Which.Code.Should().Be("clients.secrets.replaced");
    }

    private static async Task<IReadOnlyList<ZeeKayDaConfigurationFailure>> FailuresFor(ServiceCollection services)
    {
        var context = new StartupVerificationContext();
        await new ClientSecretsRegistrationVerifier(new ServiceLifetimeScanner(services))
            .VerifyAsync(context, TestContext.Current.CancellationToken);
        return context.Failures;
    }

    private sealed class HostClientSecrets : IClientSecrets
    {
        public ClientSecret Create(string plaintext) => throw new NotImplementedException();
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => throw new NotImplementedException();
        public bool Verify(ReadOnlySpan<char> presented, IReadOnlyCollection<ClientSecret> stored) =>
            throw new NotImplementedException();
    }
}
