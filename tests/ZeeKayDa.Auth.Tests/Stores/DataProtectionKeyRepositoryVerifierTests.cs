using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// The startup warning for a host that left the stores' Data Protection key ring on the runtime's
/// default storage: recorded outside Development, with App Service wording where that default differs.
/// </summary>
public sealed class DataProtectionKeyRepositoryVerifierTests : IDisposable
{
    private readonly DirectoryInfo _keyDirectory = Directory.CreateTempSubdirectory("zkda-dp-keys-");

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class EmptyXmlRepository : IXmlRepository
    {
        public IReadOnlyCollection<XElement> GetAllElements() => [];

        public void StoreElement(XElement element, string friendlyName) => throw new NotSupportedException();
    }

    public void Dispose() => _keyDirectory.Delete(recursive: true);

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void No_key_repository_outside_Development_warns_with_the_generic_text(string environment)
    {
        var context = Verify(environment, xmlRepository: null, appServiceInstanceId: null);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("data_protection.key_repository_not_configured");
        warning.Level.Should().Be(LogLevel.Warning);
        warning.MessageTemplate.Should().Be(DataProtectionKeyRepositoryVerifier.NotConfiguredMessage);
    }

    [Fact]
    public void No_key_repository_on_Azure_App_Service_warns_with_the_App_Service_text()
    {
        var context = Verify("Production", xmlRepository: null, appServiceInstanceId: "a1b2c3");

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("data_protection.key_repository_not_configured");
        warning.Level.Should().Be(LogLevel.Warning);
        warning.MessageTemplate.Should().Be(DataProtectionKeyRepositoryVerifier.AppServiceMessage);
    }

    [Fact]
    public void An_empty_App_Service_instance_id_is_not_App_Service()
    {
        var context = Verify("Production", xmlRepository: null, appServiceInstanceId: "");

        context.Warnings.Should().ContainSingle()
            .Which.MessageTemplate.Should().Be(DataProtectionKeyRepositoryVerifier.NotConfiguredMessage);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("a1b2c3")]
    public void A_configured_key_repository_records_nothing(string? appServiceInstanceId)
    {
        var context = Verify("Production", new EmptyXmlRepository(), appServiceInstanceId);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("a1b2c3")]
    public void No_key_repository_in_Development_records_nothing(string? appServiceInstanceId)
    {
        var context = Verify(Environments.Development, xmlRepository: null, appServiceInstanceId);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void No_key_repository_never_fails_startup()
    {
        var context = Verify("Production", xmlRepository: null, appServiceInstanceId: null);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void AddZeeKayDaAuthCore_without_a_key_repository_outside_Development_records_the_warning()
    {
        using var provider = BuildCoreProvider(persistKeys: false);

        var context = VerifyRegistered(provider);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("data_protection.key_repository_not_configured");
    }

    [Fact]
    public void AddZeeKayDaAuthCore_with_keys_persisted_to_the_file_system_records_nothing()
    {
        using var provider = BuildCoreProvider(persistKeys: true);

        var context = VerifyRegistered(provider);

        context.Warnings.Should().BeEmpty();
    }

    private static StartupVerificationContext Verify(string environment, IXmlRepository? xmlRepository, string? appServiceInstanceId)
    {
        var options = new KeyManagementOptions { XmlRepository = xmlRepository };
        var sut = new DataProtectionKeyRepositoryVerifier(Options.Create(options), new FakeHostEnvironment(environment));
        var context = new StartupVerificationContext();

        sut.Verify(context, appServiceInstanceId);

        return context;
    }

    private ServiceProvider BuildCoreProvider(bool persistKeys)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment("Production"));
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        if (persistKeys)
            services.AddDataProtection().PersistKeysToFileSystem(_keyDirectory);

        return services.BuildServiceProvider();
    }

    private static StartupVerificationContext VerifyRegistered(ServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        var sut = scope.ServiceProvider.GetServices<IStartupVerifier>().OfType<DataProtectionKeyRepositoryVerifier>().Should().ContainSingle().Which;
        var context = new StartupVerificationContext();

        sut.Verify(context, appServiceInstanceId: null);

        return context;
    }
}
