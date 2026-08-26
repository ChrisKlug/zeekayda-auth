using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class InMemoryStoreVerifierTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private const string TestStoreName = InMemoryStoreVerifier.AuthorizationCodeStoreName;

    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private static InMemoryStoreVerifier BuildSut(
        string environmentName,
        bool allowOutsideDevelopment = false,
        string storeName = TestStoreName)
    {
        return new InMemoryStoreVerifier(new FakeHostEnvironment(environmentName), storeName, allowOutsideDevelopment);
    }

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_environment_is_null()
    {
        var act = () => new InMemoryStoreVerifier(null!, TestStoreName, allowOutsideDevelopment: false);

        act.Should().Throw<ArgumentNullException>().WithParameterName("environment");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_throws_ArgumentException_when_storeName_is_null_or_whitespace(string? storeName)
    {
        var act = () => new InMemoryStoreVerifier(
            new FakeHostEnvironment(Environments.Development), storeName!, allowOutsideDevelopment: false);

        act.Should().Throw<ArgumentException>().WithParameterName("storeName");
    }

    // ── VerifyAsync: Development environment — warning only ──────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_adds_a_warning_in_Development_environment()
    {
        var sut = BuildSut(Environments.Development);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_warning_code_is_stores_inmemory_active_in_Development_environment()
    {
        var sut = BuildSut(Environments.Development);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("stores.inmemory.active");
    }

    [Theory]
    [InlineData(InMemoryStoreVerifier.AuthorizationCodeStoreName)]
    [InlineData(InMemoryStoreVerifier.RefreshTokenStoreName)]
    public async Task VerifyAsync_names_the_store_in_the_warning_args_in_Development_environment(string storeName)
    {
        var sut = BuildSut(Environments.Development, storeName: storeName);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Args.Should().Contain(storeName);
    }

    // ── VerifyAsync: non-Development, flag false — failure ───────────────────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task VerifyAsync_adds_a_failure_outside_Development_when_flag_is_false(string environmentName)
    {
        var sut = BuildSut(environmentName, allowOutsideDevelopment: false);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle();
        context.Warnings.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task VerifyAsync_failure_code_is_stores_inmemory_non_development_outside_Development_when_flag_is_false(
        string environmentName)
    {
        var sut = BuildSut(environmentName, allowOutsideDevelopment: false);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.inmemory.non_development");
    }

    [Fact]
    public async Task VerifyAsync_failure_message_mentions_allowOutsideDevelopment_when_flag_is_false()
    {
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: false);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Failures.Single().Message.Should().Contain("allowOutsideDevelopment");
    }

    // ── VerifyAsync: non-Development, flag true — warning, no failure ────────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task VerifyAsync_does_not_add_a_failure_outside_Development_when_flag_is_true(string environmentName)
    {
        var sut = BuildSut(environmentName, allowOutsideDevelopment: true);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task VerifyAsync_adds_a_Critical_warning_outside_Development_when_flag_is_true(string environmentName)
    {
        var sut = BuildSut(environmentName, allowOutsideDevelopment: true);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Critical);
    }

    [Fact]
    public async Task VerifyAsync_warning_code_is_stores_inmemory_non_development_override_when_flag_is_true()
    {
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: true);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("stores.inmemory.non_development_override");
    }

    [Theory]
    [InlineData(InMemoryStoreVerifier.AuthorizationCodeStoreName)]
    [InlineData(InMemoryStoreVerifier.RefreshTokenStoreName)]
    public async Task VerifyAsync_names_the_store_in_the_Critical_override_warning_args(string storeName)
    {
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: true, storeName: storeName);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Args.Should().Contain(storeName);
    }

    // ── Name: per-instance, includes the captured store name ─────────────────────────────────────

    [Theory]
    [InlineData(InMemoryStoreVerifier.AuthorizationCodeStoreName)]
    [InlineData(InMemoryStoreVerifier.RefreshTokenStoreName)]
    public void Name_includes_the_captured_store_name(string storeName)
    {
        var sut = BuildSut(Environments.Development, storeName: storeName);

        sut.Name.Should().Be($"InMemoryStore({storeName})");
    }

    // ── Two factory registrations are independent (acceptance criterion) ────────────────────────

    [Fact]
    public async Task Two_factory_registered_instances_with_different_captured_state_produce_independent_outcomes()
    {
        // Mirrors AddInMemoryStores(): AddSingleton<IStartupVerifier> called twice with the same
        // implementation type but distinct captured storeName/allowOutsideDevelopment state.
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment(Environments.Production));
        services.AddSingleton<IStartupVerifier>(sp => new InMemoryStoreVerifier(
            sp.GetRequiredService<IHostEnvironment>(),
            InMemoryStoreVerifier.AuthorizationCodeStoreName,
            allowOutsideDevelopment: false));
        services.AddSingleton<IStartupVerifier>(sp => new InMemoryStoreVerifier(
            sp.GetRequiredService<IHostEnvironment>(),
            InMemoryStoreVerifier.RefreshTokenStoreName,
            allowOutsideDevelopment: true));

        using var provider = services.BuildServiceProvider();
        var verifiers = provider.GetServices<IStartupVerifier>().ToList();

        verifiers.Should().HaveCount(2, "AddSingleton, not TryAddEnumerable, must keep both registrations");

        var authCodeContext = new StartupVerificationContext();
        var refreshTokenContext = new StartupVerificationContext();

        await verifiers[0].VerifyAsync(authCodeContext, provider, TestContext.Current.CancellationToken);
        await verifiers[1].VerifyAsync(refreshTokenContext, provider, TestContext.Current.CancellationToken);

        // The authorization-code registration (allowOutsideDevelopment: false) fails closed outside Development.
        authCodeContext.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.inmemory.non_development");
        authCodeContext.Warnings.Should().BeEmpty();

        // The refresh-token registration (allowOutsideDevelopment: true) instead warns at Critical.
        refreshTokenContext.Failures.Should().BeEmpty();
        refreshTokenContext.Warnings.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Critical);

        verifiers[0].Name.Should().Be($"InMemoryStore({InMemoryStoreVerifier.AuthorizationCodeStoreName})");
        verifiers[1].Name.Should().Be($"InMemoryStore({InMemoryStoreVerifier.RefreshTokenStoreName})");
    }

    [Fact]
    public async Task Both_in_memory_stores_report_a_failure_naming_their_own_store()
    {
        // The runner collapses failures identical in code and message within a phase. Two stores are
        // two broken registrations, so each failure must name its own store or the operator fixes
        // one, restarts, and meets the other.
        var authorizationCodes = BuildSut("Production", storeName: "authorization code store");
        var refreshTokens = BuildSut("Production", storeName: "refresh token store");
        using var provider = new ServiceCollection().BuildServiceProvider();
        var first = new StartupVerificationContext();
        var second = new StartupVerificationContext();

        await authorizationCodes.VerifyAsync(first, provider, TestContext.Current.CancellationToken);
        await refreshTokens.VerifyAsync(second, provider, TestContext.Current.CancellationToken);

        first.Failures.Single().Message.Should().Contain("authorization code store");
        second.Failures.Single().Message.Should().Contain("refresh token store");
        first.Failures.Single().Message.Should().NotBe(second.Failures.Single().Message);
    }
}
