using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderAuthenticatorExtensionsTests
{
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
