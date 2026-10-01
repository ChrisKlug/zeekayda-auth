using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderHasherExtensionsTests
{
    // ── Registration ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddClientSecretHasher_registers_hasher_as_IClientSecretHasher()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddClientSecretHasher<FakeHasher>();

        using var provider = services.BuildServiceProvider();
        var hashers = provider.GetServices<IClientSecretHasher>();
        hashers.Should().ContainSingle(h => h is FakeHasher);
    }

    [Fact]
    public void AddClientSecretHasher_registers_multiple_hashers_when_called_multiple_times()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddClientSecretHasher<FakeHasher>(isDefault: true);
        builder.AddClientSecretHasher<AnotherFakeHasher>(isDefault: false);

        using var provider = services.BuildServiceProvider();
        var hashers = provider.GetServices<IClientSecretHasher>().ToList();
        hashers.Should().HaveCount(2);
    }

    [Fact]
    public void AddClientSecretHasher_records_registration_in_options()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddClientSecretHasher<FakeHasher>(isDefault: true);

        using var provider = services.BuildServiceProvider();
        var opts = provider.GetRequiredService<IOptions<ClientSecretHasherRegistrationOptions>>().Value;
        opts.Registrations.Should().ContainSingle(r =>
            r.HasherType == typeof(FakeHasher) && r.IsDefault);
    }

    [Fact]
    public void AddClientSecretHasher_throws_InvalidOperationException_if_same_type_registered_twice()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddClientSecretHasher<FakeHasher>();

        var act = () => builder.AddClientSecretHasher<FakeHasher>();

        act.Should().Throw<InvalidOperationException>().WithMessage("*FakeHasher*");
    }

    // ── PBKDF2 iteration count ───────────────────────────────────────────────────────────────────

    private static ServiceProvider BuildWithPbkdf2Iterations(int iterations)
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com")
            .ConfigurePbkdf2ClientSecretHasher(options => options.Iterations = iterations);
        // Only so the options validators have nothing else to report.
        services.AddSingleton<IClientRepository, EmptyClientRepository>();
        return services.BuildServiceProvider();
    }

    private sealed class EmptyClientRepository : IClientRepository
    {
        public Task<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
            => Task.FromResult<IClientRegistration?>(null);
    }

    [Fact]
    public void Pbkdf2_iteration_count_configured_by_the_host_is_used_for_new_secrets()
    {
        using var provider = BuildWithPbkdf2Iterations(1_200_000);

        var created = provider.GetRequiredService<IClientSecretFactory>().Create("a-client-secret");

        created.Should().BeOfType<Pbkdf2ClientSecret>().Which.Iterations.Should().Be(1_200_000);
    }

    [Theory]
    [InlineData(599_999)]
    [InlineData(2_000_001)]
    public void Pbkdf2_iteration_count_outside_the_allowed_range_fails_startup(int iterations)
    {
        using var provider = BuildWithPbkdf2Iterations(iterations);

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(provider);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.pbkdf2.iterations_out_of_range"
                && f.Message.Contains("Pbkdf2ClientSecretHasherOptions.Iterations"));
    }

    [Theory]
    [InlineData(599_999)]
    [InlineData(2_000_001)]
    public void Pbkdf2_hasher_cannot_be_built_from_DI_with_an_iteration_count_outside_the_allowed_range(int iterations)
    {
        // The hasher trusts its options, so no DI path may hand it an unvalidated count: above the
        // cap its timing decoy would verify instantly and the failure-path padding would pad nothing.
        using var provider = BuildWithPbkdf2Iterations(iterations);

        var act = () => provider.GetServices<IClientSecretHasher>().ToList();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.pbkdf2.iterations_out_of_range");
    }

    [Fact]
    public void Pbkdf2_iteration_count_set_with_Configure_is_used_for_new_secrets()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        services.Configure<Pbkdf2ClientSecretHasherOptions>(options => options.Iterations = 1_200_000);
        using var provider = services.BuildServiceProvider();

        var created = provider.GetRequiredService<IClientSecretFactory>().Create("a-client-secret");

        created.Should().BeOfType<Pbkdf2ClientSecret>().Which.Iterations.Should().Be(1_200_000);
    }

    [Fact]
    public void Pbkdf2_hasher_refuses_an_out_of_range_count_from_a_host_registered_options_monitor()
    {
        // A host-registered IOptionsMonitor<T> bypasses the validator; the hasher's own guard stops it.
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IOptionsMonitor<Pbkdf2ClientSecretHasherOptions>>(
            new FixedMonitor(new Pbkdf2ClientSecretHasherOptions { Iterations = 2_000_001 }));
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetServices<IClientSecretHasher>().ToList();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.pbkdf2.iterations_out_of_range");
    }

    private sealed class FixedMonitor(Pbkdf2ClientSecretHasherOptions value) : IOptionsMonitor<Pbkdf2ClientSecretHasherOptions>
    {
        public Pbkdf2ClientSecretHasherOptions CurrentValue => value;
        public Pbkdf2ClientSecretHasherOptions Get(string? name) => value;
        public IDisposable? OnChange(Action<Pbkdf2ClientSecretHasherOptions, string?> listener) => null;
    }

    [Fact]
    public void Pbkdf2_hasher_reads_the_validated_iteration_count_even_when_a_host_registers_IOptions_directly()
    {
        // A direct IOptions<T> registration bypasses the options factory and its validators. The
        // hasher must not read it, or an out-of-range count would reach the timing decoy unchecked.
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton(Options.Create(new Pbkdf2ClientSecretHasherOptions { Iterations = 2_000_001 }));
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var created = provider.GetRequiredService<IClientSecretFactory>().Create("a-client-secret");

        created.Should().BeOfType<Pbkdf2ClientSecret>()
            .Which.Iterations.Should().Be(Pbkdf2ClientSecretHasherOptions.DefaultIterations);
    }

    // ── Fakes ─────────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeSecret : IClientSecret { public IClientCredential Snapshot() => new FakeSecret(); }
    private sealed class AnotherFakeSecret : IClientSecret { public IClientCredential Snapshot() => new AnotherFakeSecret(); }

    private sealed class FakeHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is FakeSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new FakeSecret();
    }

    private sealed class AnotherFakeHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is AnotherFakeSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new AnotherFakeSecret();
    }
}
