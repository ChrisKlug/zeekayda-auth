using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.AspNetCore.Extensions;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderAuthenticatorExtensionsTests
{
    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddClientAuthenticator_throws_ArgumentNullException_if_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddClientAuthenticator<FakeAuthenticator>();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── Registration ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddClientAuthenticator_registers_authenticator_as_IClientAuthenticator()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddClientAuthenticator<FakeAuthenticator>();

        using var provider = services.BuildServiceProvider();
        var authenticators = provider.GetServices<IClientAuthenticator>();
        authenticators.Should().ContainSingle(a => a is FakeAuthenticator);
    }

    [Fact]
    public void AddClientAuthenticator_registers_multiple_authenticators_when_called_multiple_times()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddClientAuthenticator<FakeAuthenticator>();
        builder.AddClientAuthenticator<AnotherFakeAuthenticator>();

        using var provider = services.BuildServiceProvider();
        var authenticators = provider.GetServices<IClientAuthenticator>().ToList();
        authenticators.Should().HaveCount(2);
    }

    [Fact]
    public void AddClientAuthenticator_registers_authenticator_as_singleton()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddClientAuthenticator<FakeAuthenticator>();

        using var provider = services.BuildServiceProvider();
        var first = provider.GetServices<IClientAuthenticator>().OfType<FakeAuthenticator>().Single();
        var second = provider.GetServices<IClientAuthenticator>().OfType<FakeAuthenticator>().Single();
        first.Should().BeSameAs(second);
    }

    [Fact]
    public void AddClientAuthenticator_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddClientAuthenticator<FakeAuthenticator>();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddClientAuthenticator_throws_InvalidOperationException_if_same_type_registered_twice()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddClientAuthenticator<FakeAuthenticator>();

        var act = () => builder.AddClientAuthenticator<FakeAuthenticator>();

        act.Should().Throw<InvalidOperationException>().WithMessage("*FakeAuthenticator*");
    }

    // ── Fakes ─────────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeAuthenticator : IClientAuthenticator
    {
        public IReadOnlySet<string> AuthenticationMethods =>
            new HashSet<string>(StringComparer.Ordinal) { "fake_method" };

        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = null;
            return false;
        }

        public ValueTask<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult(ClientAuthenticationResult.NotValid());
    }

    private sealed class AnotherFakeAuthenticator : IClientAuthenticator
    {
        public IReadOnlySet<string> AuthenticationMethods =>
            new HashSet<string>(StringComparer.Ordinal) { "another_fake_method" };

        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = null;
            return false;
        }

        public ValueTask<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult(ClientAuthenticationResult.NotValid());
    }
}
