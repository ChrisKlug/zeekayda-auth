using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Extensions;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderHasherExtensionsTests
{
    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddSecretsHasher_NullBuilder_ThrowsArgumentNullException()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddSecretsHasher<FakeHasher>();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── Registration ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddSecretsHasher_RegistersHasherAsIClientSecretHasher()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddSecretsHasher<FakeHasher>();

        using var provider = services.BuildServiceProvider();
        var hashers = provider.GetServices<IClientSecretHasher>();
        hashers.Should().ContainSingle(h => h is FakeHasher);
    }

    [Fact]
    public void AddSecretsHasher_MultipleCalls_RegisterMultipleHashers()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddSecretsHasher<FakeHasher>(isDefault: true);
        builder.AddSecretsHasher<AnotherFakeHasher>(isDefault: false);

        using var provider = services.BuildServiceProvider();
        var hashers = provider.GetServices<IClientSecretHasher>().ToList();
        hashers.Should().HaveCount(2);
    }

    [Fact]
    public void AddSecretsHasher_RecordsRegistrationInOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddSecretsHasher<FakeHasher>(isDefault: true);

        using var provider = services.BuildServiceProvider();
        var opts = provider.GetRequiredService<IOptions<ClientSecretHasherRegistrationOptions>>().Value;
        opts.Registrations.Should().ContainSingle(r =>
            r.HasherType == typeof(FakeHasher) && r.IsDefault);
    }

    [Fact]
    public void AddSecretsHasher_ReturnsBuilder_ForChaining()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddSecretsHasher<FakeHasher>();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddSecretsHasher_SameTypeTwice_ThrowsInvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddSecretsHasher<FakeHasher>();

        var act = () => builder.AddSecretsHasher<FakeHasher>();

        act.Should().Throw<InvalidOperationException>().WithMessage("*FakeHasher*");
    }

    // ── AddPbkdf2SecretsHasher ───────────────────────────────────────────────────────────────────

    [Fact]
    public void AddPbkdf2SecretsHasher_NullBuilder_ThrowsArgumentNullException()
    {
        ZeeKayDaAuthBuilder builder = null!;
        var act = () => builder.AddPbkdf2SecretsHasher();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddPbkdf2SecretsHasher_RegistersPbkdf2HasherAsIClientSecretHasher()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddPbkdf2SecretsHasher();

        using var provider = services.BuildServiceProvider();
        var hashers = provider.GetServices<IClientSecretHasher>();
        hashers.Should().ContainSingle(h => h is Pbkdf2ClientSecretHasher);
    }

    [Fact]
    public void AddPbkdf2SecretsHasher_WithoutConfigure_UsesDefaultIterations()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddPbkdf2SecretsHasher();

        using var provider = services.BuildServiceProvider();
        var opts = provider.GetRequiredService<IOptions<Pbkdf2ClientSecretHasherOptions>>().Value;
        opts.Iterations.Should().Be(Pbkdf2ClientSecretHasherOptions.DefaultIterations);
    }

    [Fact]
    public void AddPbkdf2SecretsHasher_WithConfigure_AppliesConfiguration()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddPbkdf2SecretsHasher(options => options.Iterations = 1_200_000);

        using var provider = services.BuildServiceProvider();
        var opts = provider.GetRequiredService<IOptions<Pbkdf2ClientSecretHasherOptions>>().Value;
        opts.Iterations.Should().Be(1_200_000);
    }

    [Fact]
    public void AddPbkdf2SecretsHasher_ReturnsBuilder_ForChaining()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddPbkdf2SecretsHasher();

        returned.Should().BeSameAs(builder);
    }

    // ── Fakes ─────────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeSecret : IClientSecret { }
    private sealed class AnotherFakeSecret : IClientSecret { }

    private sealed class FakeHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is FakeSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(string plaintext) => new FakeSecret();
    }

    private sealed class AnotherFakeHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is AnotherFakeSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(string plaintext) => new AnotherFakeSecret();
    }
}
